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

fn validate_mecmcp_lockfile(lock: &str) -> Result<(), String> {
    let source = format!("git+{REPOSITORY}?tag={TAG}#{COMMIT}");
    let mut expected = PACKAGES
        .map(|package| (package.to_owned(), VERSION.to_owned(), source.clone()))
        .to_vec();
    let document = lock
        .parse::<toml::Table>()
        .map_err(|error| format!("lockfile must be valid TOML: {error}"))?;
    let package_tables = document
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "lockfile must contain package tables".to_owned())?;
    let mut actual = Vec::new();
    for (index, package) in package_tables.iter().enumerate() {
        let table = package
            .as_table()
            .ok_or_else(|| format!("lockfile package {index} must be a table"))?;
        let name = table
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("lockfile package {index} must have a string name"))?;
        if !name.starts_with("mecmcp-") {
            continue;
        }
        let version = table
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{name} lockfile block lacks a version"))?;
        let package_source = table
            .get("source")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{name} lockfile block lacks a source"))?;
        actual.push((
            name.to_owned(),
            version.to_owned(),
            package_source.to_owned(),
        ));
    }

    expected.sort();
    actual.sort();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "lockfile mecmcp package tuples differ from the exact approved set: {actual:?}"
        ))
    }
}

#[test]
fn all_mecmcp_crates_use_one_released_tag_and_commit() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_root.join("../..");
    let manifest =
        fs::read_to_string(workspace_root.join("Cargo.toml")).expect("read workspace manifest");
    let lock =
        fs::read_to_string(workspace_root.join("Cargo.lock")).expect("read workspace lockfile");

    for package in PACKAGES {
        let declaration = format!(
            r#"{package} = {{ version = "{VERSION}", git = "{REPOSITORY}", tag = "{TAG}" }}"#
        );
        assert!(
            manifest.lines().any(|line| line == declaration),
            "{package} must use the exact coherent workspace declaration"
        );
    }

    validate_mecmcp_lockfile(&lock).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn rejects_rogue_mecmcp_package_from_another_source() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut lock =
        fs::read_to_string(crate_root.join("../../Cargo.lock")).expect("read workspace lockfile");
    lock.push_str(
        r#"
[[package]]
name = "mecmcp-rogue"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    );

    assert!(
        validate_mecmcp_lockfile(&lock).is_err(),
        "an alternate-source mecmcp package must invalidate the dependency contract"
    );
}

#[test]
fn rejects_noncanonical_toml_rogue_packages() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock =
        fs::read_to_string(crate_root.join("../../Cargo.lock")).expect("read workspace lockfile");
    let rogue_blocks = [
        (
            "indented keys",
            r#"
[[package]]
    name = "mecmcp-indented"
    version = "0.3.7"
    source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        ),
        (
            "literal strings",
            r#"
[[package]]
name = 'mecmcp-literal'
version = '0.3.7'
source = 'registry+https://github.com/rust-lang/crates.io-index'
"#,
        ),
        (
            "spaced array-table header",
            r#"
[[ package ]]
name = "mecmcp-spaced-header"
version = "0.3.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        ),
    ];

    for (case, rogue_block) in rogue_blocks {
        let candidate = format!("{lock}{rogue_block}");
        candidate
            .parse::<toml::Table>()
            .unwrap_or_else(|error| panic!("{case} fixture must be valid TOML: {error}"));
        assert!(
            validate_mecmcp_lockfile(&candidate).is_err(),
            "{case} must not hide a rogue mecmcp package"
        );
    }
}

#[test]
fn rejects_any_non_exact_mecmcp_package_set() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock =
        fs::read_to_string(crate_root.join("../../Cargo.lock")).expect("read workspace lockfile");
    let approved_source = format!("git+{REPOSITORY}?tag={TAG}#{COMMIT}");
    let auth_block = lock
        .split("[[package]]")
        .find(|block| block.contains("\nname = \"mecmcp-auth\"\n"))
        .expect("mecmcp-auth package block");

    let mut extra = lock.clone();
    extra.push_str(
        r#"
[[package]]
name = "mecmcp-rogue"
version = "0.3.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    );
    let duplicate = format!("{lock}\n[[package]]{auth_block}");
    let missing = lock.replacen(&format!("[[package]]{auth_block}"), "", 1);
    let wrong_source = lock.replacen(
        &approved_source,
        "git+https://example.invalid/mecmcp?tag=changeset-v0.3.7#85137c509fe1803b87e8636462f0392ce05072ce",
        1,
    );
    let wrong_version = lock.replacen(
        "name = \"mecmcp-auth\"\nversion = \"0.3.7\"",
        "name = \"mecmcp-auth\"\nversion = \"0.3.8\"",
        1,
    );

    for (case, candidate) in [
        ("extra", extra),
        ("duplicate", duplicate),
        ("missing", missing),
        ("different source", wrong_source),
        ("different version", wrong_version),
    ] {
        assert!(
            validate_mecmcp_lockfile(&candidate).is_err(),
            "{case} mecmcp package set must be rejected"
        );
    }
}
