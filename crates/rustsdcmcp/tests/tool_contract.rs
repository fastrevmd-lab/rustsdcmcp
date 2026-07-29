//! Security tripwires for MCP tool and HTTP preflight registries.

use mecmcp_transport::{MalformedArgumentsPolicy, TargetField, ToolScopePreflight};
use rustsdcmcp::{KNOWN_TOOLS, WRITE_TOOLS};
use std::collections::BTreeSet;

#[test]
fn tool_registry_has_expected_unique_surface() {
    assert_eq!(KNOWN_TOOLS.len(), 17);
    assert_eq!(
        KNOWN_TOOLS.iter().copied().collect::<BTreeSet<_>>().len(),
        KNOWN_TOOLS.len()
    );
    assert_eq!(
        WRITE_TOOLS.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "apply_sdc_change_set",
            "approve_sdc_change_set",
            "prepare_sdc_policy_deploy",
        ])
    );
}

#[test]
fn shared_preflight_can_enforce_the_tenant_target() {
    let _preflight = ToolScopePreflight::new(
        WRITE_TOOLS,
        [TargetField::scalar("tenant")],
        MalformedArgumentsPolicy::Deny,
    );
}
