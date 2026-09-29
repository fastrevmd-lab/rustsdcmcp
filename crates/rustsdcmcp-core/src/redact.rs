//! Credential redaction for tool output.
//!
//! Applied at the MCP tool boundary only, never inside [`crate::SdcClient`],
//! for the reason `projection.rs` gives: change-control reads the same
//! endpoints to capture before-state, and redacting there would hide drift.
//!
//! Generic key- and value-shape redaction (`secret`, `token`, `password`,
//! `psk`, `private_key`, `community`, `api_key`, crypt hashes, PEM blocks,
//! ...) is delegated to the shared [`mecmcp_redact`] crate, which every
//! mechub MCP server uses so a new denylist entry or value shape lands once,
//! not per server (MEC-345's shared-crate migration; MEC-14 H1b).
//!
//! Two things stay local, because they are SDC-specific knowledge the shared
//! crate deliberately does not have (see its `projection` module docs: "the
//! actual field lists for UniFi and SDC resources are declared by those
//! servers, not here"):
//!
//! - `site_config` and `cpe_config` are withheld **as a whole**, not
//!   key-scanned. They are rendered device configuration bodies in a format
//!   SDC does not document, and SDC-generated IPsec config carries the IKE
//!   pre-shared key inline; there is no guarantee the shared crate's
//!   line-oriented scan recognizes every secret shape SDC's CPE templates can
//!   produce, so the whole body is dropped rather than trusted to a
//!   best-effort scan. This runs *before* the shared-crate pass.
//! - [`NON_SECRET_KEYS`] exempts our own opaque paging cursors
//!   (`continuation_token`, and the upstream `nextPageToken` it mirrors) from
//!   the shared crate's `token` denylist match; redacting them breaks paging
//!   (MEC-440 B1). Protected before the shared-crate pass, restored after.
//!
//! ## Redaction policy
//!
//! `finish_redacted` is used for every read tool, with no per-family
//! exemption; see `REDACTED_TOOLS` in `tests/tool_contract.rs` for the
//! enforced, exhaustive list. Write tools (`prepare_*`/`apply_*`/
//! `approve_*`/`discard_*`) go through `finish_redacted` too: `prepare_*`
//! results echo the raw upstream before-state in `prepared_change`, and
//! `apply_*` results return a `plan: {before, after}`, so they carry the same
//! upstream fields the read path redacts. Only the tool output is redacted —
//! the stored action, the plan digest and the change-set id are untouched, so
//! approve/apply work unchanged.

use serde_json::Value;

/// Marker substituted for a redacted value. Re-exported so callers building
/// their own fixtures can assert against it without duplicating the string.
pub const REDACTED: &str = "[REDACTED]";

/// Upstream field names withheld as a whole rather than key/value scanned.
///
/// `site_config` and `cpe_config` are not themselves credentials — they are
/// rendered device configuration bodies, and SDC-generated IPsec config
/// carries the IKE pre-shared key, so both are withheld as a whole rather
/// than trusted to the shared crate's line scan.
///
/// Each key is normalized (lowercased, `_` and `-` removed) before
/// comparison, so `siteConfig` and `site-config` match too.
const WHOLESALE_REDACT_KEYS: &[&str] = &["siteconfig", "cpeconfig"];

/// Keys that must survive the shared crate's `token` denylist match: opaque
/// paging cursors the caller must echo back to page past the first page.
/// Exact match after normalization, at any depth.
const NON_SECRET_KEYS: &[&str] = &["continuationtoken", "nextpagetoken"];

/// Prefix used to hide a paging-token key from the shared crate's denylist
/// scan for the duration of that pass. Not valid in a normal upstream JSON
/// key, so it cannot collide with a real field.
const PAGING_GUARD_PREFIX: &str = "\u{0}mecmcp-paging-guard\u{0}";

/// Normalize a key for comparison: lowercase and remove `_` and `-`.
fn normalize_key(key: &str) -> String {
    key.to_ascii_lowercase()
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect()
}

/// Replace every credential-bearing value in `value`, at any depth.
///
/// `null` stays `null`: it carries no secret, and rewriting it would claim
/// one existed.
#[must_use]
pub fn redact_secrets(mut value: Value) -> Value {
    redact_wholesale_fields(&mut value);
    let paging_tokens = guard_paging_tokens(&mut value);
    mecmcp_redact::redact_json_value(&mut value);
    unguard_paging_tokens(&mut value, &paging_tokens);
    value
}

/// Redact license keys in an RMA state response.
///
/// Replaces each element of the top-level `missing_licenses` array with the
/// REDACTED marker, preserving array length so the count stays visible. The
/// spec describes `missing_licenses` as "Array of license keys that are missing",
/// so the keys are the array VALUES, not object keys.
///
/// Fails closed: if `missing_licenses` is present but not an array (API
/// regression), the entire value is replaced with REDACTED. `null` stays `null`.
///
/// Other fields are left untouched. This is SDC-specific business logic
/// (license keys, not credentials), so it stays local rather than moving to
/// the shared crate.
#[must_use]
pub fn redact_rma_state(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut()
        && let Some(licenses) = obj.get_mut("missing_licenses")
    {
        if let Some(arr) = licenses.as_array_mut() {
            for item in arr.iter_mut() {
                *item = Value::String(REDACTED.to_owned());
            }
        } else if !licenses.is_null() {
            // Fail closed: non-array, non-null → replace wholesale
            *licenses = Value::String(REDACTED.to_owned());
        }
    }
    value
}

/// Replace any [`WHOLESALE_REDACT_KEYS`] value with [`REDACTED`], at any
/// depth, before the shared crate's key/value scan ever sees it.
fn redact_wholesale_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if WHOLESALE_REDACT_KEYS.contains(&normalize_key(key).as_str()) {
                    if !child.is_null() {
                        *child = Value::String(REDACTED.to_owned());
                    }
                } else {
                    redact_wholesale_fields(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_wholesale_fields),
        _ => {}
    }
}

/// Rename every [`NON_SECRET_KEYS`] key to an opaque, counter-suffixed
/// placeholder so the shared crate's substring denylist scan never sees a
/// `token`-shaped name, and record the original names in traversal order so
/// [`unguard_paging_tokens`] can restore them exactly.
///
/// The placeholder cannot embed the original key text (e.g. by prefixing it):
/// `continuation_token` normalized is itself `continuationtoken`, which
/// contains the denylisted substring `token`, so a prefix-only marker would
/// still trip the scan it exists to dodge. A pure counter carries no such
/// text.
#[must_use]
fn guard_paging_tokens(value: &mut Value) -> Vec<String> {
    let mut originals = Vec::new();
    guard_inner(value, &mut originals);
    originals
}

fn guard_inner(value: &mut Value, originals: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if NON_SECRET_KEYS.contains(&normalize_key(&key).as_str())
                    && let Some(v) = map.remove(&key)
                {
                    let marker = format!("{PAGING_GUARD_PREFIX}{}", originals.len());
                    originals.push(key);
                    map.insert(marker, v);
                }
            }
            for (_, child) in map.iter_mut() {
                guard_inner(child, originals);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| guard_inner(v, originals)),
        _ => {}
    }
}

/// Reverse [`guard_paging_tokens`], restoring the original key names from
/// `originals` by the counter each placeholder carries.
fn unguard_paging_tokens(value: &mut Value, originals: &[String]) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let Some(index) = key
                    .strip_prefix(PAGING_GUARD_PREFIX)
                    .and_then(|suffix| suffix.parse::<usize>().ok())
                else {
                    continue;
                };
                let Some(original) = originals.get(index) else {
                    continue;
                };
                if let Some(v) = map.remove(&key) {
                    map.insert(original.clone(), v);
                }
            }
            for (_, child) in map.iter_mut() {
                unguard_paging_tokens(child, originals);
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|v| unguard_paging_tokens(v, originals)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn paging_tokens_survive_redaction() {
        // Percy B1 (MEC-440): the compound `*token` match redacted #172's
        // ListPage.continuation_token, breaking paging past page 1. The
        // shared mecmcp-redact crate has the identical `token` substring on
        // its denylist, so the guard/unguard round trip must still hold.
        let items: Vec<Value> = (0..2)
            .map(|i| serde_json::json!({ "id": i, "blob": "x".repeat(40 * 1024) }))
            .collect();
        let page = crate::paging::page_list(
            &serde_json::json!({ "versions": items }),
            "versions",
            None,
            None,
            64 * 1024,
        )
        .expect("page");
        let token = page.continuation_token.clone().expect("a next page");
        let redacted = redact_secrets(serde_json::to_value(&page).expect("serialize"));
        assert_eq!(redacted["continuation_token"], Value::String(token));

        let upstream = redact_secrets(serde_json::json!({
            "nextPageToken": "abc", "accessToken": "QQsecret"
        }));
        assert_eq!(upstream["nextPageToken"], "abc");
        assert_eq!(upstream["accessToken"], REDACTED);
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn icap_server_passwords_are_redacted_in_a_list_envelope() {
        let listed = json!({"items": [{
            "uuid": "u1", "name": "icap", "host": "10.0.0.1",
            "password_ascii": "hunter2", "password_base64": "aHVudGVyMg=="
        }], "count": 1});
        let out = redact_secrets(listed);
        assert_eq!(out["items"][0]["password_ascii"], REDACTED);
        assert_eq!(out["items"][0]["password_base64"], REDACTED);
        assert_eq!(out["items"][0]["host"], "10.0.0.1");
        assert_eq!(out["count"], 1);
    }

    #[test]
    fn nested_site_psk_and_config_body_are_redacted() {
        let site = json!({"site": {"site_name": "s1", "cpe_devices": [{
            "name": "cpe",
            "cpe_config": {"body": "...pre-shared-key...", "format": "set"},
            "mist_config": {"pre_shared_key": "k"},
            "cpe_interfaces": [{
                "psk": "shared", "ike_id": "id",
                "site_config": {"body": "set security ike ... pre-shared-key", "format": "set"}
            }]
        }]}});
        let out = redact_secrets(site);
        let device = &out["site"]["cpe_devices"][0];
        assert_eq!(device["cpe_config"], REDACTED);
        assert_eq!(device["mist_config"]["pre_shared_key"], REDACTED);
        let iface = &device["cpe_interfaces"][0];
        assert_eq!(iface["psk"], REDACTED);
        assert_eq!(iface["site_config"], REDACTED);
        assert_eq!(iface["ike_id"], "id");
    }

    #[test]
    fn key_match_is_case_insensitive_and_null_is_left_alone() {
        let out = redact_secrets(json!({"PSK": "x", "password": null}));
        assert_eq!(out["PSK"], REDACTED);
        assert!(out["password"].is_null());
    }

    #[test]
    fn a_value_without_credentials_is_unchanged() {
        let original = json!({"items": [{"name": "a", "keysize": "2048"}]});
        assert_eq!(redact_secrets(original.clone()), original);
    }

    #[test]
    fn camel_case_and_hyphenated_keys_are_redacted() {
        let out = redact_secrets(json!({
            "preSharedKey": "secret1",
            "cpeConfig": {"body": "config"},
            "siteConfig": {"format": "set"},
            "passwordBase64": "c2VjcmV0",
            "keysize": "2048",
            "pskHint": "over-redacted-on-purpose"
        }));
        assert_eq!(out["preSharedKey"], REDACTED);
        assert_eq!(out["cpeConfig"], REDACTED);
        assert_eq!(out["siteConfig"], REDACTED);
        assert_eq!(out["passwordBase64"], REDACTED);
        // Unrelated to any denylisted term: survives.
        assert_eq!(out["keysize"], "2048");
        // Unlike the old hand-rolled denylist (which deliberately excluded
        // `psk` from compound matching), the shared crate's `psk` denylist
        // entry substring-matches `pskHint` too. Over-redaction is the
        // shared crate's documented, accepted direction to be wrong in.
        assert_eq!(out["pskHint"], REDACTED);
    }

    #[test]
    fn secret_key_is_redacted() {
        let out = redact_secrets(json!({"secret": "hunter2", "name": "a"}));
        assert_eq!(out["secret"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    #[test]
    fn token_key_is_redacted() {
        let out = redact_secrets(json!({"token": "abc123", "name": "a"}));
        assert_eq!(out["token"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    #[test]
    fn api_key_is_redacted() {
        let out = redact_secrets(json!({"api_key": "abc123", "apiKey": "def456", "name": "a"}));
        assert_eq!(out["api_key"], REDACTED);
        assert_eq!(out["apiKey"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    #[test]
    fn private_key_is_redacted() {
        // A synthetic, non-PEM-shaped placeholder: a real PEM body here trips
        // the full-history Gitleaks scan on every future squash merge (a new
        // commit SHA needs a new `.gitleaksignore` entry each time).
        let out = redact_secrets(json!({
            "private_key": "synthetic-private-key-material",
            "public_key_algorithm": "rsa"
        }));
        assert_eq!(out["private_key"], REDACTED);
        // Public key metadata is not a secret and must survive.
        assert_eq!(out["public_key_algorithm"], "rsa");
    }

    #[test]
    fn community_string_is_redacted() {
        let out = redact_secrets(json!({"community": "public", "name": "a"}));
        assert_eq!(out["community"], REDACTED);
        assert_eq!(out["name"], "a");
    }

    /// Compound key names, which never equal a shared-crate denylist entry
    /// exactly, are still caught by its prefix/suffix substring match.
    #[test]
    fn compound_credential_key_names_are_redacted() {
        let out = redact_secrets(json!({
            "accessToken": "a",
            "authToken": "b",
            "apiToken": "c",
            "clientSecret": "d",
            "snmpCommunity": "e",
            "communityString": "f",
            "privateKeyPem": "g",
            "current_password": "h",
            "name": "unaffected",
        }));
        for key in [
            "accessToken",
            "authToken",
            "apiToken",
            "clientSecret",
            "snmpCommunity",
            "communityString",
            "privateKeyPem",
            "current_password",
        ] {
            assert_eq!(out[key], REDACTED, "{key} should be redacted");
        }
        assert_eq!(out["name"], "unaffected");
    }

    /// Proves IPS/ECF-shaped output is still redacted after the shared-crate
    /// migration (MEC-345 closed the local gap; MEC-14 H1b swapped the
    /// backend). Before MEC-345, IPS/ECF handlers called plain `finish` and
    /// skipped redaction entirely.
    #[test]
    fn ips_and_ecf_shaped_responses_are_redacted() {
        let ips_rule = json!({
            "uuid": "r1",
            "name": "block-scan",
            "community": "public",
            "action": "drop"
        });
        let out = redact_secrets(ips_rule);
        assert_eq!(out["community"], REDACTED);
        assert_eq!(out["action"], "drop");

        let ecf_rule_set = json!({
            "items": [{"uuid": "s1", "name": "blocklist", "token": "ecf-abc123"}],
            "count": 1
        });
        let out = redact_secrets(ecf_rule_set);
        assert_eq!(out["items"][0]["token"], REDACTED);
        assert_eq!(out["items"][0]["name"], "blocklist");
        assert_eq!(out["count"], 1);
    }

    #[test]
    fn rma_state_missing_licenses_are_redacted() {
        let state = json!({
            "device_id": "dev1",
            "rma_state": "ACTIVE",
            "missing_licenses": ["LIC-KEY-123", "LIC-KEY-456", "LIC-KEY-789"],
            "other_field": "untouched"
        });
        let out = redact_rma_state(state);
        assert_eq!(
            out["missing_licenses"]
                .as_array()
                .expect("missing_licenses should be an array")
                .len(),
            3
        );
        assert_eq!(out["missing_licenses"][0], REDACTED);
        assert_eq!(out["missing_licenses"][1], REDACTED);
        assert_eq!(out["missing_licenses"][2], REDACTED);
        assert_eq!(out["device_id"], "dev1");
        assert_eq!(out["other_field"], "untouched");
    }

    #[test]
    fn rma_state_without_missing_licenses_is_unchanged() {
        let state = json!({"device_id": "dev1", "rma_state": "ACTIVE"});
        let out = redact_rma_state(state.clone());
        assert_eq!(out, state);
    }

    #[test]
    fn rma_state_empty_missing_licenses_stays_empty() {
        let state = json!({"missing_licenses": []});
        let out = redact_rma_state(state);
        assert_eq!(
            out["missing_licenses"]
                .as_array()
                .expect("missing_licenses should be an array")
                .len(),
            0
        );
    }

    #[test]
    fn rma_state_non_array_missing_licenses_is_redacted() {
        // Fail closed: if missing_licenses is a string (API regression), redact it
        let state = json!({"device_id": "dev1", "missing_licenses": "LIC-KEY-MALFORMED"});
        let out = redact_rma_state(state);
        assert_eq!(out["missing_licenses"], REDACTED);
        assert_eq!(out["device_id"], "dev1");
    }

    #[test]
    fn rma_state_null_missing_licenses_stays_null() {
        // null carries no secret, so leave it alone
        let state = json!({"device_id": "dev1", "missing_licenses": null});
        let out = redact_rma_state(state);
        assert!(out["missing_licenses"].is_null());
        assert_eq!(out["device_id"], "dev1");
    }
}
