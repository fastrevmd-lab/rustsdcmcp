//! Credential redaction for tool output.
//!
//! Applied at the MCP tool boundary only, never inside [`crate::SdcClient`],
//! for the reason `projection.rs` gives: change-control reads the same
//! endpoints to capture before-state, and redacting there would hide drift.
//!
//! This is a **denylist**, unlike the certificate allowlists. The families it
//! guards (ICAP servers, v2 sites, device config, image definitions and job status,
//! MNHA sync status, RMA state and reactivation status) are deeply nested and have
//! never been observed on the lab tenant, so there is no observed field set to
//! allowlist. A present-but-redacted marker is used instead of removal so a caller
//! can see the field exists without learning its value.
//!
//! ## Redaction policy
//!
//! `finish_redacted` is used for every family whose response shape has not been
//! observed live, or whose schema declares a credential or rendered-config field.
//! IPS and ECF families use plain `finish` because the spec declares no such
//! fields for them.

use serde_json::Value;

/// Marker substituted for a redacted value.
pub const REDACTED: &str = "[REDACTED]";

/// Keys whose values are credentials, compared case- and separator-insensitively.
///
/// `site_config` and `cpe_config` are not themselves credentials. They are
/// rendered device configuration bodies, and SDC-generated IPsec config carries
/// the IKE pre-shared key, so both are withheld as a whole.
///
/// Each key is normalized (lowercased, `_` and `-` removed) before comparison,
/// so `preSharedKey`, `pre_shared_key`, and `PRE-SHARED-KEY` all match.
const SECRET_KEYS: &[&str] = &[
    "password",
    "password_ascii",
    "password_base64",
    "passphrase",
    "psk",
    "pre_shared_key",
    "site_config",
    "cpe_config",
];

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
    redact_in_place(&mut value);
    value
}

/// Redact license keys in an RMA state response.
///
/// Replaces each element of the top-level `missing_licenses` array with the
/// REDACTED marker, preserving array length so the count stays visible. The
/// spec describes `missing_licenses` as "Array of license keys that are missing",
/// so the keys are the array VALUES, not object keys.
///
/// Other fields are left untouched.
#[must_use]
pub fn redact_rma_state(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut()
        && let Some(licenses) = obj.get_mut("missing_licenses")
        && let Some(arr) = licenses.as_array_mut()
    {
        for item in arr.iter_mut() {
            *item = Value::String(REDACTED.to_owned());
        }
    }
    value
}

fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let normalized = normalize_key(key);
                let is_secret = SECRET_KEYS
                    .iter()
                    .any(|secret| normalize_key(secret) == normalized);
                if is_secret {
                    if !child.is_null() {
                        *child = Value::String(REDACTED.to_owned());
                    }
                } else {
                    redact_in_place(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_in_place),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
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
            "pskHint": "not-a-secret"
        }));
        assert_eq!(out["preSharedKey"], REDACTED);
        assert_eq!(out["cpeConfig"], REDACTED);
        assert_eq!(out["siteConfig"], REDACTED);
        assert_eq!(out["passwordBase64"], REDACTED);
        // These should NOT be redacted
        assert_eq!(out["keysize"], "2048");
        assert_eq!(out["pskHint"], "not-a-secret");
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
}
