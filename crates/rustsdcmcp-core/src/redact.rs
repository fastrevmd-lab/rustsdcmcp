//! Credential redaction for tool output.
//!
//! Applied at the MCP tool boundary only, never inside [`crate::SdcClient`],
//! for the reason `projection.rs` gives: change-control reads the same
//! endpoints to capture before-state, and redacting there would hide drift.
//!
//! This is a **denylist**, unlike the certificate allowlists. The families it
//! guards (ICAP servers, v2 sites) are deeply nested and have never been
//! observed on the lab tenant, so there is no observed field set to allowlist.
//! A present-but-redacted marker is used instead of removal so a caller can
//! see the field exists without learning its value.

use serde_json::Value;

/// Marker substituted for a redacted value.
pub const REDACTED: &str = "[REDACTED]";

/// Keys whose values are credentials, compared case-insensitively.
///
/// `site_config` and `cpe_config` are not themselves credentials. They are
/// rendered device configuration bodies, and SDC-generated IPsec config carries
/// the IKE pre-shared key, so both are withheld as a whole.
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

/// Replace every credential-bearing value in `value`, at any depth.
///
/// `null` stays `null`: it carries no secret, and rewriting it would claim
/// one existed.
#[must_use]
pub fn redact_secrets(mut value: Value) -> Value {
    redact_in_place(&mut value);
    value
}

fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let lowered = key.to_ascii_lowercase();
                if SECRET_KEYS.contains(&lowered.as_str()) {
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
}
