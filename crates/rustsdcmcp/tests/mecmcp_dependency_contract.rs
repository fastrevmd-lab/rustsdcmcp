//! Enforces the coherent released mecmcp dependency pin.

use std::{fs, path::Path};

const PACKAGES: [&str; 5] = [
    "mecmcp-audit",
    "mecmcp-auth",
    "mecmcp-changeset",
    "mecmcp-runtime",
    "mecmcp-transport",
];
const VERSION: &str = "0.3.7";
const TAG: &str = "changeset-v0.3.7";
const COMMIT: &str = "85137c509fe1803b87e8636462f0392ce05072ce";
const REPOSITORY: &str = "https://github.com/fastrevmd-lab/mecmcp";

#[test]
fn all_mecmcp_crates_use_one_released_tag_and_commit() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_root.join("../..");
    let manifest = fs::read_to_string(workspace_root.join("Cargo.toml"))
        .expect("read workspace manifest");
    let lock = fs::read_to_string(workspace_root.join("Cargo.lock"))
        .expect("read workspace lockfile");

    for package in PACKAGES {
        let declaration = format!(
            r#"{package} = {{ version = "{VERSION}", git = "{REPOSITORY}", tag = "{TAG}" }}"#
        );
        assert!(
            manifest.lines().any(|line| line == declaration),
            "{package} must use the exact coherent workspace declaration"
        );

        let marker = format!("\nname = \"{package}\"\n");
        let block = lock
            .split("[[package]]")
            .find(|block| block.contains(&marker))
            .unwrap_or_else(|| panic!("missing {package} lockfile block"));
        assert!(block.contains(&format!("\nversion = \"{VERSION}\"\n")));
        assert!(block.contains(&format!(
            "\nsource = \"git+{REPOSITORY}?tag={TAG}#{COMMIT}\"\n"
        )));
    }

    let mecmcp_blocks = lock
        .split("[[package]]")
        .filter(|block| block.contains(&format!("git+{REPOSITORY}?")))
        .count();
    assert_eq!(
        mecmcp_blocks,
        PACKAGES.len(),
        "lockfile must contain exactly the five expected mecmcp git packages"
    );
}
