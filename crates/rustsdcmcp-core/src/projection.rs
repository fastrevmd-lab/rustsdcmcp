//! Field allowlists for certificate and licence reads.
//!
//! Certificates and licences are the only surfaces whose responses could
//! plausibly carry material that is sensitive in kind rather than merely in
//! scope — key material, CSRs, or passphrases. Live capture on 2026-08-12 found
//! none of that; the responses are metadata only. The allowlist exists for the
//! case that has no observation, which is any field upstream adds later. With
//! passthrough there is no point at which such a field would be noticed; it
//! would simply start flowing to callers.
//!
//! # Where this is applied, and why not lower
//!
//! **At the MCP tool boundary only, never inside [`crate::SdcClient`].**
//!
//! Projection is a presentation concern. The change-control path reads the same
//! certificate and licence endpoints through the client to capture before-state
//! — `prepare_license_write` digests that value, and apply compares against it
//! to detect drift. Projecting in the client would erase an unknown field from
//! *both* sides of that comparison, so a write whose target had drifted in that
//! field would apply as unchanged. The client therefore returns upstream JSON
//! verbatim, exactly as every other reader does, and a test pins that.
//!
//! # What is projected
//!
//! The allowlists below contain exactly the fields observed on a live tenant,
//! and nothing inferred. A field upstream adds is dropped and its *name* is
//! logged, so the addition is visible and can be allowlisted deliberately.
//! Names only are logged, never values.
//!
//! Collection envelopes (`items`, `count`) pass through unprojected. Sensitive
//! material would live on the certificate objects, not alongside them, and
//! projecting the envelope risks silently discarding a pagination field that
//! upstream adds. Unknown envelope keys are logged as *preserved*, with wording
//! distinct from the dropped-field warning — a warning that said "dropped"
//! would tell an operator the field never reached callers when in fact it did.

use crate::SdcError;
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

/// Envelope keys observed on every certificate/licence collection response.
const ENVELOPE_FIELDS: &[&str] = &["items", "count"];

/// Fields observed on `ListUsers` items (`/api/v2/users`).
///
/// No `created`/`created_by` field exists anywhere on this resource — see
/// `SdcClient::list_users`. `role` is a nested list of role references,
/// further restricted to [`USER_ROLE_REF_FIELDS`] after this allowlist runs.
const USER_FIELDS: &[&str] = &["user_id", "email", "name", "status", "last_login", "role"];

/// Fields observed on each `role[]` entry nested inside a `ListUsers` item.
///
/// A user's `role` entries are role *references*, not the full role object
/// `ListRoles` returns, and carry only a name in the vendored spec.
const USER_ROLE_REF_FIELDS: &[&str] = &["role_name"];

/// Fields observed on `ListRoles` items (`/api/v2/roles`).
const ROLE_FIELDS: &[&str] = &["UUID", "name", "capabilities", "predefined"];

/// Envelope keys observed on the `ListUsers` response.
const USER_ENVELOPE_FIELDS: &[&str] = &["users", "user_count"];

/// Envelope keys observed on the `ListRoles` response.
const ROLE_ENVELOPE_FIELDS: &[&str] = &["roles", "role_count"];

/// Project a CA-certificate collection onto its allowlist.
pub fn project_ca_certificates(value: Value) -> Result<Value, SdcError> {
    project_collection(
        value,
        "items",
        ENVELOPE_FIELDS,
        CA_CERTIFICATE_FIELDS,
        "ca_certificates",
    )
}

/// Project a local-certificate collection onto its allowlist.
pub fn project_local_certificates(value: Value) -> Result<Value, SdcError> {
    project_collection(
        value,
        "items",
        ENVELOPE_FIELDS,
        LOCAL_CERTIFICATE_FIELDS,
        "local_certificates",
    )
}

/// Project a licence collection onto its allowlist.
pub fn project_licenses(value: Value) -> Result<Value, SdcError> {
    project_collection(value, "items", ENVELOPE_FIELDS, LICENSE_FIELDS, "licenses")
}

/// Project a single licence object onto its allowlist.
pub fn project_license(value: Value) -> Result<Value, SdcError> {
    match value {
        Value::Object(object) => Ok(Value::Object(retain_allowed(
            object,
            LICENSE_FIELDS,
            "license",
        ))),
        // Fail closed. A response that is not an object cannot be projected,
        // and passing it through would carry unallowlisted content across the
        // MCP boundary on exactly the surface this module exists to guard.
        _ => Err(SdcError::InvalidJson),
    }
}

/// Project each member of an `{"<items_key>": [...], ...}` envelope.
///
/// An empty tenant returns a bare `{}`, which has no `items_key` and is
/// returned as-is. Any other departure from the expected shape fails closed
/// with [`SdcError::InvalidJson`] rather than passing unprojected content
/// through the boundary this module exists to guard.
fn project_collection(
    value: Value,
    items_key: &str,
    envelope_fields: &[&str],
    allowed: &[&str],
    surface: &str,
) -> Result<Value, SdcError> {
    let Value::Object(mut envelope) = value else {
        return Err(SdcError::InvalidJson);
    };

    let unknown_envelope: Vec<&str> = envelope
        .keys()
        .map(String::as_str)
        .filter(|key| !envelope_fields.contains(key))
        .collect();
    if !unknown_envelope.is_empty() {
        report_preserved_envelope(surface, &unknown_envelope);
    }

    let items = match envelope.remove(items_key) {
        Some(Value::Array(items)) => items,
        // `items_key` present but not an array. Fail closed rather than
        // passing it through: an object-valued collection would carry
        // arbitrary unprojected content to the caller, defeating the
        // allowlist entirely.
        Some(_) => return Err(SdcError::InvalidJson),
        // An empty tenant returns a bare `{}` with no items key at all.
        None => return Ok(Value::Object(envelope)),
    };

    let mut dropped: Vec<String> = Vec::new();
    let mut projected: Vec<Value> = Vec::with_capacity(items.len());
    for item in items {
        // Fail closed on a non-object member for the same reason as a
        // non-array collection: it cannot be projected, and a nested array
        // could carry objects the allowlist never inspects.
        let Value::Object(object) = item else {
            return Err(SdcError::InvalidJson);
        };
        for key in object.keys() {
            if !allowed.contains(&key.as_str()) && !dropped.contains(key) {
                dropped.push(key.clone());
            }
        }
        projected.push(Value::Object(retain_only(object, allowed)));
    }

    if !dropped.is_empty() {
        let names: Vec<&str> = dropped.iter().map(String::as_str).collect();
        report_dropped(surface, "item", &names);
    }

    envelope.insert(items_key.to_owned(), Value::Array(projected));
    Ok(Value::Object(envelope))
}

/// Project a `ListUsers` response onto [`USER_FIELDS`], further restricting
/// each nested `role[]` reference to [`USER_ROLE_REF_FIELDS`].
fn project_users(value: Value) -> Result<Value, SdcError> {
    let projected = project_collection(value, "users", USER_ENVELOPE_FIELDS, USER_FIELDS, "users")?;
    let Value::Object(mut envelope) = projected else {
        return Err(SdcError::InvalidJson);
    };
    if let Some(Value::Array(items)) = envelope.get_mut("users") {
        for item in items.iter_mut() {
            let Value::Object(object) = item else {
                return Err(SdcError::InvalidJson);
            };
            if let Some(role_refs) = object.remove("role") {
                object.insert("role".to_owned(), project_role_refs(role_refs)?);
            }
        }
    }
    Ok(Value::Object(envelope))
}

/// Project one user's `role[]` array onto [`USER_ROLE_REF_FIELDS`].
fn project_role_refs(value: Value) -> Result<Value, SdcError> {
    let Value::Array(refs) = value else {
        return Err(SdcError::InvalidJson);
    };
    let mut dropped: Vec<String> = Vec::new();
    let mut projected: Vec<Value> = Vec::with_capacity(refs.len());
    for entry in refs {
        let Value::Object(object) = entry else {
            return Err(SdcError::InvalidJson);
        };
        for key in object.keys() {
            if !USER_ROLE_REF_FIELDS.contains(&key.as_str()) && !dropped.contains(key) {
                dropped.push(key.clone());
            }
        }
        projected.push(Value::Object(retain_only(object, USER_ROLE_REF_FIELDS)));
    }
    if !dropped.is_empty() {
        let names: Vec<&str> = dropped.iter().map(String::as_str).collect();
        report_dropped("users", "role_ref", &names);
    }
    Ok(Value::Array(projected))
}

/// Project a `ListRoles` response onto [`ROLE_FIELDS`].
fn project_roles(value: Value) -> Result<Value, SdcError> {
    project_collection(value, "roles", ROLE_ENVELOPE_FIELDS, ROLE_FIELDS, "roles")
}

/// Project the combined `list_users_and_roles` response, `{"users": ...,
/// "roles": ...}`, onto the users and roles allowlists.
///
/// The "metadata only" promise this tool's description makes rests on this
/// allowlist, not on [`crate::redact_secrets`]'s key-name denylist alone: an
/// upstream field the vendored spec doesn't declare (an activation link, an
/// MFA seed, a recovery code) would pass a denylist unless its key happened
/// to match a known secret pattern. This projects onto exactly the fields
/// the tool's description promises, and drops everything else.
pub fn project_users_and_roles(value: Value) -> Result<Value, SdcError> {
    let Value::Object(mut outer) = value else {
        return Err(SdcError::InvalidJson);
    };
    let users = match outer.remove("users") {
        Some(users) => project_users(users)?,
        None => return Err(SdcError::InvalidJson),
    };
    let roles = match outer.remove("roles") {
        Some(roles) => project_roles(roles)?,
        None => return Err(SdcError::InvalidJson),
    };
    Ok(serde_json::json!({ "users": users, "roles": roles }))
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
        report_dropped(surface, "object", &dropped);
    }
    retain_only(object, allowed)
}

/// Retain allowed keys on one object without reporting.
fn retain_only(mut object: Map<String, Value>, allowed: &[&str]) -> Map<String, Value> {
    object.retain(|key, _| allowed.contains(&key.as_str()));
    object
}

/// Log the names of fields excluded by an allowlist and withheld from callers.
///
/// Names only. A value is never logged, because the reason a field is unknown
/// may be that it carries something that must not reach a log.
fn report_dropped(surface: &str, scope: &str, names: &[&str]) {
    tracing::warn!(
        surface,
        scope,
        fields = names.join(","),
        "dropped fields absent from the certificate/licence allowlist; \
         these did NOT reach the caller. Upstream may have added fields that \
         should be reviewed and allowlisted"
    );
}

/// Log unknown envelope keys, which are **preserved** rather than dropped.
///
/// Kept distinct from [`report_dropped`] deliberately. These warnings are the
/// signal that upstream changed something, so one that said "dropped" here
/// would tell an operator the field never reached callers when in fact it did.
fn report_preserved_envelope(surface: &str, names: &[&str]) {
    tracing::warn!(
        surface,
        scope = "envelope",
        fields = names.join(","),
        "unrecognized envelope fields were PRESERVED and returned to the \
         caller unprojected; only item fields are allowlisted. Review whether \
         these should be projected"
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
                "uuid": "00000000-0000-4000-8000-000000000001",
                "name": "sd_cloud_local",
                "private_key": "-----BEGIN PRIVATE KEY-----AAAA-----END PRIVATE KEY-----",
                "passphrase": "hunter2",
            }],
            "count": 1,
        });

        let projected = project_local_certificates(response).expect("projects");
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

        let projected = project_local_certificates(response).expect("projects");
        let item = &projected["items"][0];

        assert_eq!(item["public_key_algorithm"], "rsaEncryption");
        assert_eq!(item["key_size"], "2048");
    }

    #[test]
    fn every_observed_ca_certificate_field_survives() {
        let response = json!({
            "items": [{
                "uuid": "00000000-0000-4000-8000-000000000002",
                "name": "ISRG_Root_X1",
                "device_uuid": "00000000-0000-4000-8000-000000000003",
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

        let projected = project_ca_certificates(response.clone()).expect("projects");

        assert_eq!(
            projected["items"][0], response["items"][0],
            "a live-captured CA certificate must survive projection unchanged"
        );
    }

    #[test]
    fn every_observed_licence_field_survives() {
        let licence = json!({
            "uuid": "00000000-0000-4000-8000-000000000004",
            "name": "E20210617001",
            "version": "4",
            "state": "valid",
            "validity_type": "date-based",
            "start_date": "2026-06-17",
            "end_date": "2026-08-16",
        });

        assert_eq!(project_license(licence.clone()).expect("projects"), licence);
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
        assert_eq!(project_licenses(json!({})).expect("projects"), json!({}));
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

        let projected = project_licenses(response).expect("projects");

        assert_eq!(projected["next_page_token"], "abc");
        assert_eq!(projected["count"], 1);
        assert!(projected["items"][0].get("surprise").is_none());
        assert_eq!(projected["items"][0]["uuid"], "u");
    }

    #[test]
    fn malformed_collections_fail_closed() {
        // An object-valued `items` would otherwise reach the caller verbatim,
        // carrying arbitrary unprojected content across the boundary this
        // module guards. Refuse rather than pass through.
        for malformed in [
            json!({"items": null, "count": 0}),
            json!({"items": {"private_key": "leaked"}}),
            json!({"items": [["nested"]]}),
            json!({"items": ["scalar"]}),
        ] {
            assert!(
                project_licenses(malformed.clone()).is_err(),
                "malformed collection must be refused, not passed through: {malformed}"
            );
        }
    }

    #[test]
    fn non_object_response_fails_closed() {
        assert!(project_licenses(json!([1, 2])).is_err());
        assert!(project_license(json!("nope")).is_err());
    }

    #[test]
    fn iam_fields_outside_the_allowlist_are_dropped_from_users_and_roles() {
        // A denylist keyed on secret-shaped names would miss all of these:
        // `activation_link` and `note` don't look like secrets by key name,
        // and `credentials`/`recovery_codes` carry nested structure a flat
        // key-name scan wouldn't recurse into consistently. The allowlist
        // must drop them regardless of what they're named.
        let response = json!({
            "users": {
                "users": [{
                    "user_id": "u1",
                    "email": "soc@example.com",
                    "name": "SOC Reader",
                    "status": "pending",
                    "last_login": "2026-09-01T00:00:00Z",
                    "activation_link": "https://sdc.example.com/activate?code=abc123",
                    "mfa_seed": "JBSWY3DPEHPK3PXP",
                    "recovery_codes": ["11112222", "33334444"],
                    "credentials": {"key": "$9$abcXYZ"},
                    "note": "backup pw $9$abcXYZ",
                    "role": [{"role_name": "viewer", "role_id": "r1", "scope": "internal"}],
                }],
                "user_count": "1",
            },
            "roles": {
                "roles": [{
                    "UUID": "r1",
                    "name": "viewer",
                    "capabilities": ["read"],
                    "predefined": true,
                    "password": "hunter2",
                }],
                "role_count": "1",
            },
        });

        let projected = project_users_and_roles(response).expect("projects");
        let user = &projected["users"]["users"][0];
        let role_ref = &user["role"][0];
        let role = &projected["roles"]["roles"][0];

        assert!(user.get("activation_link").is_none());
        assert!(user.get("mfa_seed").is_none());
        assert!(user.get("recovery_codes").is_none());
        assert!(user.get("credentials").is_none());
        assert!(user.get("note").is_none());
        assert!(role_ref.get("role_id").is_none());
        assert!(role_ref.get("scope").is_none());
        assert_eq!(role_ref["role_name"], "viewer");
        assert!(role.get("password").is_none());
        assert_eq!(user["name"], "SOC Reader");
        assert_eq!(user["user_id"], "u1");
        assert_eq!(projected["users"]["user_count"], "1");
        assert_eq!(role["name"], "viewer");
        assert_eq!(projected["roles"]["role_count"], "1");
    }

    #[test]
    fn every_observed_iam_field_survives_users_and_roles_projection() {
        let response = json!({
            "users": {
                "users": [{
                    "user_id": "u1",
                    "email": "soc@example.com",
                    "name": "SOC Reader",
                    "status": "active",
                    "last_login": "2026-09-01T00:00:00Z",
                    "role": [{"role_name": "viewer"}],
                }],
                "user_count": "1",
            },
            "roles": {
                "roles": [{
                    "UUID": "r1",
                    "name": "viewer",
                    "capabilities": ["read"],
                    "predefined": true,
                }],
                "role_count": "1",
            },
        });

        assert_eq!(
            project_users_and_roles(response.clone()).expect("projects"),
            response,
            "a live-shaped users/roles response must survive projection unchanged"
        );
    }

    #[test]
    fn empty_users_and_roles_tenant_is_unchanged() {
        let response = json!({"users": {}, "roles": {}});
        assert_eq!(
            project_users_and_roles(response.clone()).expect("projects"),
            response
        );
    }
}
