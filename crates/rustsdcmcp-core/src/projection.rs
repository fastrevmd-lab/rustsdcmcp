//! Field allowlists for certificate and licence reads.
//!
//! Every other reader on [`crate::SdcClient`] passes upstream JSON through
//! verbatim. Certificates and licences do not, because they are the only
//! surfaces whose responses could plausibly carry material that is sensitive in
//! kind rather than merely in scope — key material, CSRs, or passphrases.
//!
//! Live capture on 2026-08-12 found none of that: the responses are metadata
//! only. The allowlist exists for the case that has no observation, which is
//! any field upstream adds later. With passthrough there is no point at which
//! such a field would be noticed; it would simply start flowing to callers.
//!
//! The allowlists below therefore contain exactly the fields observed on a live
//! tenant, and nothing inferred. A field that upstream adds is dropped and its
//! *name* is logged, so the addition is visible and can be allowlisted
//! deliberately. Names only are logged, never values.
//!
//! Collection envelopes (`items`, `count`) pass through unprojected. Sensitive
//! material would live on the certificate objects, not alongside them, and
//! projecting the envelope risks silently discarding a pagination field that
//! upstream adds. Unknown envelope keys are logged for the same visibility.

use serde_json::{Map, Value};

/// Fields observed on `ListCaCertificates` and `ListDeviceCaCertificates`.
///
/// `device_uuid` is returned only by the tenant-wide list; the per-device
/// variant omits it. One allowlist covers both.
///
/// The locality and state fields appear on some certificates and not others —
/// they are the optional `L=` and `ST=` components of an X.509 distinguished
/// name. Sampling one item is therefore not enough to derive this list; it was
/// taken from the union of keys across every item on a live tenant.
const CA_CERTIFICATE_FIELDS: &[&str] = &[
    "uuid",
    "name",
    "device_uuid",
    "common_name",
    "distinguished_name",
    "organization_name",
    "locality_name",
    "state_or_province_name",
    "public_key_algorithm",
    "key_size",
    "serial_number",
    "expiry_date",
    "signature_algorithm",
    "finger_print_content",
    "issuer_common_name",
    "issuer_organization_name",
    "issuer_locality_name",
    "issuer_state_or_province_name",
];

/// Fields observed on `ListLocalCertificates` and `ListDeviceLocalCertificates`.
///
/// `public_key_algorithm` and `key_size` describe the *public* key and are not
/// secrets, despite matching a naive `key` substring rule.
const LOCAL_CERTIFICATE_FIELDS: &[&str] = &[
    "uuid",
    "name",
    "device_uuid",
    "distinguished_name",
    "public_key_algorithm",
    "serial_number",
    "validity_not_before",
    "validity_not_after",
    "key_size",
    "signature_algorithm",
    "finger_print_content",
    "auto_re_enrollment_status",
    "auto_re_enrollment_trigger_time",
    "email",
    "subject_alternate_domain_name",
    "ipv4_address",
    "ipv6_address",
];

/// Fields observed on `ListLicenses` and `GetLicense`.
///
/// `GetLicense` returns exactly the list-item field set; unlike devices, the
/// single-object read adds nothing.
const LICENSE_FIELDS: &[&str] = &[
    "uuid",
    "name",
    "version",
    "state",
    "validity_type",
    "start_date",
    "end_date",
];

/// Envelope keys observed on every collection response.
const ENVELOPE_FIELDS: &[&str] = &["items", "count"];

/// Project a CA-certificate collection onto its allowlist.
pub(crate) fn project_ca_certificates(value: Value) -> Value {
    project_collection(value, CA_CERTIFICATE_FIELDS, "ca_certificates")
}

/// Project a local-certificate collection onto its allowlist.
pub(crate) fn project_local_certificates(value: Value) -> Value {
    project_collection(value, LOCAL_CERTIFICATE_FIELDS, "local_certificates")
}

/// Project a licence collection onto its allowlist.
pub(crate) fn project_licenses(value: Value) -> Value {
    project_collection(value, LICENSE_FIELDS, "licenses")
}

/// Project a single licence object onto its allowlist.
pub(crate) fn project_license(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(retain_allowed(object, LICENSE_FIELDS, "license")),
        other => other,
    }
}

/// Project each member of an `{"items": [...], "count": N}` envelope.
///
/// A response that is not that shape is returned unchanged. An empty tenant
/// returns a bare `{}`, which has no `items` to project.
fn project_collection(value: Value, allowed: &[&str], surface: &str) -> Value {
    let Value::Object(mut envelope) = value else {
        return value;
    };

    let unknown_envelope: Vec<&str> = envelope
        .keys()
        .map(String::as_str)
        .filter(|key| !ENVELOPE_FIELDS.contains(key))
        .collect();
    if !unknown_envelope.is_empty() {
        report_unknown(surface, "envelope", &unknown_envelope);
    }

    let Some(Value::Array(items)) = envelope.remove("items") else {
        // Either no `items` key, or it is not an array. Restore nothing and
        // return what remains; the caller sees the response unmodified.
        return Value::Object(envelope);
    };

    let mut dropped: Vec<String> = Vec::new();
    let projected: Vec<Value> = items
        .into_iter()
        .map(|item| match item {
            Value::Object(object) => {
                for key in object.keys() {
                    if !allowed.contains(&key.as_str()) && !dropped.contains(key) {
                        dropped.push(key.clone());
                    }
                }
                Value::Object(retain_only(object, allowed))
            }
            other => other,
        })
        .collect();

    if !dropped.is_empty() {
        let names: Vec<&str> = dropped.iter().map(String::as_str).collect();
        report_unknown(surface, "item", &names);
    }

    envelope.insert("items".to_owned(), Value::Array(projected));
    Value::Object(envelope)
}

/// Retain allowed keys on one object, reporting the names of any dropped.
fn retain_allowed(
    object: Map<String, Value>,
    allowed: &[&str],
    surface: &str,
) -> Map<String, Value> {
    let dropped: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if !dropped.is_empty() {
        report_unknown(surface, "object", &dropped);
    }
    retain_only(object, allowed)
}

/// Retain allowed keys on one object without reporting.
fn retain_only(mut object: Map<String, Value>, allowed: &[&str]) -> Map<String, Value> {
    object.retain(|key, _| allowed.contains(&key.as_str()));
    object
}

/// Log the names of fields excluded by an allowlist.
///
/// Names only. A value is never logged, because the reason a field is unknown
/// may be that it carries something that must not reach a log.
fn report_unknown(surface: &str, scope: &str, names: &[&str]) {
    tracing::warn!(
        surface,
        scope,
        fields = names.join(","),
        "dropped fields absent from the certificate/licence allowlist; \
         upstream may have added fields that should be reviewed and allowlisted"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn injected_private_key_is_dropped_from_local_certificates() {
        let response = json!({
            "items": [{
                "uuid": "d0e9c237-7e45-4565-a36b-f8115bd88b9e",
                "name": "sd_cloud_local",
                "private_key": "-----BEGIN PRIVATE KEY-----AAAA-----END PRIVATE KEY-----",
                "passphrase": "hunter2",
            }],
            "count": 1,
        });

        let projected = project_local_certificates(response);
        let item = &projected["items"][0];

        assert!(item.get("private_key").is_none());
        assert!(item.get("passphrase").is_none());
        assert_eq!(item["name"], "sd_cloud_local");
        assert_eq!(projected["count"], 1);
    }

    #[test]
    fn public_key_metadata_survives_projection() {
        // A denylist keyed on the substring `key` would wrongly drop both of
        // these. They describe the public key and are not secrets.
        let response = json!({
            "items": [{"public_key_algorithm": "rsaEncryption", "key_size": "2048"}],
            "count": 1,
        });

        let projected = project_local_certificates(response);
        let item = &projected["items"][0];

        assert_eq!(item["public_key_algorithm"], "rsaEncryption");
        assert_eq!(item["key_size"], "2048");
    }

    #[test]
    fn every_observed_ca_certificate_field_survives() {
        let response = json!({
            "items": [{
                "uuid": "54fd5da0-22c5-44ec-a774-27888d4d6d4b",
                "name": "ISRG_Root_X1",
                "device_uuid": "a0f049c4-903a-471e-93c2-f8d19d30cebc",
                "common_name": "ISRG Root X1",
                "distinguished_name": "C=US, O=Internet Security Research Group, CN=ISRG Root X1",
                "organization_name": "Internet Security Research Group",
                "public_key_algorithm": "rsaEncryption",
                "key_size": "4096",
                "serial_number": "0x8210cfb0d240e3594463e0bb63828b00",
                "expiry_date": "2035-06-04 11:04 UTC",
                "signature_algorithm": "sha256WithRSAEncryption",
                "finger_print_content": "ca:bd:2a:79",
                "issuer_common_name": "ISRG Root X1",
                "issuer_organization_name": "Internet Security Research Group",
            }],
            "count": 1,
        });

        let projected = project_ca_certificates(response.clone());

        assert_eq!(
            projected["items"][0], response["items"][0],
            "a live-captured CA certificate must survive projection unchanged"
        );
    }

    #[test]
    fn every_observed_licence_field_survives() {
        let licence = json!({
            "uuid": "7f1a926a-655b-4240-8e33-1cab3c426de1",
            "name": "E20210617001",
            "version": "4",
            "state": "valid",
            "validity_type": "date-based",
            "start_date": "2026-06-17",
            "end_date": "2026-08-16",
        });

        assert_eq!(project_license(licence.clone()), licence);
    }

    #[test]
    fn allowlists_cover_every_field_seen_on_the_live_tenant() {
        // The union of keys across *every* item each endpoint returned on the
        // lab tenant, 2026-08-12 — not just the first item. Sampling one item
        // missed four optional X.509 name components carried by the second CA
        // certificate, which is why this guard exists.
        const LIVE_CA: &[&str] = &[
            "common_name",
            "device_uuid",
            "distinguished_name",
            "expiry_date",
            "finger_print_content",
            "issuer_common_name",
            "issuer_locality_name",
            "issuer_organization_name",
            "issuer_state_or_province_name",
            "key_size",
            "locality_name",
            "name",
            "organization_name",
            "public_key_algorithm",
            "serial_number",
            "signature_algorithm",
            "state_or_province_name",
            "uuid",
        ];
        const LIVE_LOCAL: &[&str] = &[
            "auto_re_enrollment_status",
            "auto_re_enrollment_trigger_time",
            "device_uuid",
            "distinguished_name",
            "email",
            "finger_print_content",
            "ipv4_address",
            "ipv6_address",
            "key_size",
            "name",
            "public_key_algorithm",
            "serial_number",
            "signature_algorithm",
            "subject_alternate_domain_name",
            "uuid",
            "validity_not_after",
            "validity_not_before",
        ];
        const LIVE_LICENSE: &[&str] = &[
            "end_date",
            "name",
            "start_date",
            "state",
            "uuid",
            "validity_type",
            "version",
        ];

        for field in LIVE_CA {
            assert!(
                CA_CERTIFICATE_FIELDS.contains(field),
                "live CA certificate field {field} is not allowlisted and would be dropped"
            );
        }
        for field in LIVE_LOCAL {
            assert!(
                LOCAL_CERTIFICATE_FIELDS.contains(field),
                "live local certificate field {field} is not allowlisted and would be dropped"
            );
        }
        for field in LIVE_LICENSE {
            assert!(
                LICENSE_FIELDS.contains(field),
                "live licence field {field} is not allowlisted and would be dropped"
            );
        }
    }

    #[test]
    fn empty_tenant_response_is_unchanged() {
        // An empty collection returns a bare `{}` (see docs/sdc-api §3).
        assert_eq!(project_licenses(json!({})), json!({}));
    }

    #[test]
    fn envelope_count_and_unknown_envelope_keys_are_preserved() {
        // Envelope keys pass through so an upstream pagination field is not
        // silently discarded; only item fields are projected.
        let response = json!({
            "items": [{"uuid": "u", "surprise": 1}],
            "count": 1,
            "next_page_token": "abc",
        });

        let projected = project_licenses(response);

        assert_eq!(projected["next_page_token"], "abc");
        assert_eq!(projected["count"], 1);
        assert!(projected["items"][0].get("surprise").is_none());
        assert_eq!(projected["items"][0]["uuid"], "u");
    }

    #[test]
    fn non_object_response_is_unchanged() {
        assert_eq!(project_licenses(json!([1, 2])), json!([1, 2]));
        assert_eq!(project_license(json!("nope")), json!("nope"));
    }
}
