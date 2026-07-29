//! Enforces the temporary compatibility migration ledger.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

type LedgerEntry = (String, String, String);

fn compatibility_sources() -> Vec<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/compat");
    let mut paths = fs::read_dir(directory)
        .expect("read compatibility directory")
        .map(|entry| entry.expect("read compatibility entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect::<Vec<_>>();
    paths.sort();
    paths.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustsdcmcp-core/src/compat.rs"));
    paths.sort();
    paths
}

fn is_compat_declaration(line: &str) -> bool {
    let line = line.trim_start();
    let line = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let line = line.strip_prefix("async ").unwrap_or(line);
    let line = line.strip_prefix("const ").unwrap_or(line);
    ["fn ", "struct ", "enum ", "trait ", "type "]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

fn marker(line: &str) -> Option<LedgerEntry> {
    let remainder = line.trim_start().strip_prefix("/// mecmcp-compat: ")?;
    let fields = remainder.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields.len(), 3, "invalid compatibility marker: {line}");
    Some((
        fields[0].to_owned(),
        fields[1].to_owned(),
        fields[2].to_owned(),
    ))
}

#[test]
fn compatibility_declarations_match_the_issue_ledger() {
    let ledger_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("docs/mecmcp-compatibility.tsv");
    let ledger = fs::read_to_string(&ledger_path).expect("read compatibility ledger");
    let rows = ledger.lines().skip(1).collect::<Vec<_>>();
    assert_eq!(rows.len(), 59, "ledger must contain exactly 59 data rows");

    let mut ledger_entries = BTreeSet::new();
    let mut symbols = BTreeSet::new();
    let mut urls = BTreeSet::new();
    for row in rows {
        let fields = row.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5, "invalid ledger row: {row}");
        let entry = (
            fields[0].to_owned(),
            fields[1].to_owned(),
            fields[2].to_owned(),
        );
        assert!(
            fields[2]
                .strip_prefix("https://github.com/fastrevmd-lab/mecmcp/issues/")
                .is_some_and(
                    |number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                ),
            "ledger URL must be a full numeric mecmcp issue URL: {}",
            fields[2]
        );
        assert!(
            symbols.insert(fields[1]),
            "duplicate ledger symbol: {}",
            fields[1]
        );
        assert!(
            urls.insert(fields[2]),
            "duplicate ledger issue URL: {}",
            fields[2]
        );
        assert!(
            ledger_entries.insert(entry),
            "duplicate ledger entry: {row}"
        );
    }

    let mut source_entries = BTreeSet::new();
    for path in compatibility_sources() {
        let source = fs::read_to_string(&path).expect("read compatibility source");
        let production = source.split("\n#[cfg(test)]").next().unwrap_or(&source);
        let lines = production.lines().collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            if let Some(entry) = marker(line) {
                assert!(
                    source_entries.insert(entry),
                    "duplicate compatibility marker in {}: {line}",
                    path.display(),
                );
            }
            if is_compat_declaration(line) {
                let preceding = index.checked_sub(1).and_then(|index| lines.get(index));
                assert!(
                    preceding
                        .is_some_and(|line| line.trim_start().starts_with("/// mecmcp-compat:")),
                    "unmarked compatibility declaration in {}: {}",
                    path.display(),
                    line.trim(),
                );
            }
        }
    }

    assert_eq!(
        source_entries.len(),
        59,
        "source must contain exactly 59 markers"
    );
    assert_eq!(
        source_entries, ledger_entries,
        "source markers must match ledger"
    );
}
