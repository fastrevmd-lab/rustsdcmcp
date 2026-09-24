//! Security tripwires for MCP tool and HTTP preflight registries.

use rustsdcmcp::{KNOWN_TOOLS, WRITE_TOOLS};
use std::collections::BTreeSet;

#[test]
fn tool_registry_has_expected_unique_surface() {
    // 52 reads / 14 writes. #32 added 6 license/certificate reads (PR #49) and
    // 2 license/certificate writes; #34 added device-group list and get; #63
    // added discard_sdc_operation, which must be a write tool so a wildcard
    // scope cannot reach it; #21 added list_sdc_config_versions (read) and the
    // device-sync prepare/apply pair. #156 added list/get_sdc_sites (redacted).
    // #156 added IPS rule and exempt-rule reads.
    // #156 added ECF rule-set and rule reads.
    // #156 added three global-settings singletons and the device global-settings list.
    // #155 added device config section and revision reads.
    // #155 added image definition and job-status reads.
    // #155 added MNHA sync and RMA status reads.
    assert_eq!(KNOWN_TOOLS.len(), 73);
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

/// Tools that return credential-bearing responses use `finish_redacted`.
///
/// Reverting a redacted handler to plain `finish` would pass the existing
/// tests, because no test exercises a live credential field. This tripwire
/// fails if any REDACTED_TOOLS handler does not call `finish_redacted`, or
/// if it calls plain `finish`.
#[test]
fn redacted_tools_call_finish_redacted() {
    const REDACTED_TOOLS: &[&str] = &[
        "list_sdc_resources",
        "get_sdc_resource",
        "list_sdc_sites",
        "get_sdc_site",
        "get_sdc_firewall_global_settings",
        "get_sdc_firewall_global_profile",
        "get_sdc_content_security_settings",
        "list_sdc_device_global_settings",
    ];

    // Every REDACTED_TOOLS entry must be a known tool.
    for tool in REDACTED_TOOLS {
        assert!(
            KNOWN_TOOLS.contains(tool),
            "{tool} is in REDACTED_TOOLS but not KNOWN_TOOLS"
        );
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let server_rs = std::fs::read_to_string(format!("{manifest_dir}/src/server.rs"))
        .expect("server.rs must be readable");
    let file = syn::parse_file(&server_rs).expect("server.rs must parse");

    let mut found_tools = BTreeSet::new();

    for item in &file.items {
        if let syn::Item::Impl(impl_block) = item {
            for impl_item in &impl_block.items {
                if let syn::ImplItem::Fn(method) = impl_item {
                    // Convert method to string to search for tool names
                    let method_str = quote::quote!(#method).to_string();

                    // Check each redacted tool
                    for tool in REDACTED_TOOLS {
                        let tool_marker = format!("name = \"{}\"", tool);
                        if method_str.contains(&tool_marker) {
                            found_tools.insert(*tool);

                            assert!(
                                method_str.contains("finish_redacted"),
                                "{tool} is in REDACTED_TOOLS but does not call finish_redacted"
                            );
                            // Check that plain finish( is not called (but finish_redacted is OK)
                            // We look for "finish (" with a space to distinguish from finish_redacted
                            let has_plain_finish = method_str.contains("finish (")
                                || (method_str.contains("finish(")
                                    && !method_str.contains("finish_redacted("));
                            assert!(
                                !has_plain_finish,
                                "{tool} is in REDACTED_TOOLS but may call plain finish()"
                            );
                        }
                    }
                }
            }
        }
    }

    // Ensure we found all expected tools
    for tool in REDACTED_TOOLS {
        assert!(
            found_tools.contains(tool),
            "{tool} is in REDACTED_TOOLS but was not found in server.rs"
        );
    }
}
