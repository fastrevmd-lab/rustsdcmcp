//! Security tripwires for MCP tool and HTTP preflight registries.

use rustsdcmcp::{KNOWN_TOOLS, WRITE_TOOLS};
use std::collections::BTreeSet;

#[test]
fn tool_registry_has_expected_unique_surface() {
    assert_eq!(KNOWN_TOOLS.len(), 22);
    assert_eq!(
        KNOWN_TOOLS.iter().copied().collect::<BTreeSet<_>>().len(),
        KNOWN_TOOLS.len()
    );
    assert_eq!(
        WRITE_TOOLS.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "apply_sdc_change_set",
            "apply_sdc_object_write",
            "approve_sdc_change_set",
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
                || tool.starts_with("apply_"),
            "{tool} mutates but is not named for a change-control phase"
        );
    }
}
