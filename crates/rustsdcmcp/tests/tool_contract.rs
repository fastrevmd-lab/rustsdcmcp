//! Security tripwires for MCP tool and HTTP preflight registries.

use rustsdcmcp::{KNOWN_TOOLS, WRITE_TOOLS};
use std::collections::BTreeSet;

#[test]
fn tool_registry_has_expected_unique_surface() {
    // 40 reads / 14 writes. #32 added 6 license/certificate reads (PR #49) and
    // 2 license/certificate writes; #34 added device-group list and get; #63
    // added discard_sdc_operation, which must be a write tool so a wildcard
    // scope cannot reach it; #21 added list_sdc_config_versions (read) and the
    // device-sync prepare/apply pair.
    assert_eq!(KNOWN_TOOLS.len(), 54);
    assert_eq!(
        KNOWN_TOOLS.iter().copied().collect::<BTreeSet<_>>().len(),
        KNOWN_TOOLS.len()
    );
    assert_eq!(
        WRITE_TOOLS.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "apply_sdc_change_set",
            "apply_sdc_device_inventory_sync",
            "apply_sdc_firewall_write",
            "apply_sdc_license_write",
            "apply_sdc_nat_write",
            "apply_sdc_object_write",
            "approve_sdc_change_set",
            "discard_sdc_operation",
            "prepare_sdc_device_inventory_sync",
            "prepare_sdc_firewall_write",
            "prepare_sdc_license_write",
            "prepare_sdc_nat_write",
            "prepare_sdc_object_write",
            "prepare_sdc_policy_deploy",
        ])
    );
}

/// Reads must stay the majority of the surface.
///
/// `CLAUDE.md` requires read-only tools to land first and remain dominant, so
/// a change that tips the balance toward mutation should fail here rather than
/// pass unnoticed.
#[test]
fn read_tools_remain_the_majority_of_the_surface() {
    let writes = WRITE_TOOLS.len();
    let reads = KNOWN_TOOLS.len() - writes;
    assert!(
        reads > writes,
        "{reads} read tools must outnumber {writes} write tools"
    );
}

/// Every write tool is registered, and no read tool is silently a write.
#[test]
fn write_tools_are_all_registered_and_named_for_their_lifecycle() {
    for tool in WRITE_TOOLS {
        assert!(
            KNOWN_TOOLS.contains(tool),
            "{tool} is a write tool but is not registered"
        );
        assert!(
            tool.starts_with("prepare_")
                || tool.starts_with("approve_")
                || tool.starts_with("apply_")
                // discard is a lifecycle operation rather than a phase: it clears
                // a wedged operation so applies are unblocked, not a change-control
                // phase like prepare/approve/apply.
                || tool.starts_with("discard_"),
            "{tool} mutates but is not named for a change-control phase or lifecycle operation"
        );
    }
}

#[test]
fn a_device_group_list_accepts_an_omitted_from_and_fields() {
    // `ListArgs::from` is `#[serde(default)]`, so every other list tool accepts
    // a call without `from`. The device-group list uses its own argument type
    // to carry `fields`, and dropping that default would have broken a
    // previously valid call shape without any test noticing.
    let args: rustsdcmcp::DeviceGroupListArgs =
        serde_json::from_value(serde_json::json!({"tenant": "production", "size": 10}))
            .expect("omitting from must stay valid");
    assert_eq!(args.from, 0);
    assert!(args.fields.is_empty());

    let projected: rustsdcmcp::DeviceGroupListArgs = serde_json::from_value(
        serde_json::json!({"tenant": "production", "size": 10, "fields": ["uuid", "name"]}),
    )
    .expect("fields is a list, not a comma-joined string");
    assert_eq!(projected.fields, vec!["uuid".to_owned(), "name".to_owned()]);
}
