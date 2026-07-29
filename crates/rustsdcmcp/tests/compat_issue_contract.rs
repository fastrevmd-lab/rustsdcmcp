//! Enforces the temporary compatibility migration ledger.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use syn::{Attribute, Expr, ExprLit, ImplItem, Item, Lit, Meta, Type};

type LedgerEntry = (String, String, String);

fn compatibility_sources() -> Vec<PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/compat");
    let mut paths = Vec::new();
    discover_rs_files(&directory, &mut paths);
    paths.sort();
    paths.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustsdcmcp-core/src/compat.rs"));
    paths.sort();
    paths
}

fn discover_rs_files(directory: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read compatibility directory") {
        let path = entry.expect("read compatibility entry").path();
        if path.is_dir() {
            discover_rs_files(&path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            paths.push(path);
        }
    }
}

fn marker(remainder: &str) -> Result<LedgerEntry, String> {
    let fields = remainder.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 {
        return Err(format!("invalid compatibility marker: {remainder}"));
    }
    Ok((
        fields[0].to_owned(),
        fields[1].to_owned(),
        fields[2].to_owned(),
    ))
}

fn cfg_test(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && matches!(&attribute.meta, Meta::List(list) if list.tokens.to_string().contains("test"))
    })
}

fn marker_attribute(attributes: &[Attribute]) -> Result<Option<LedgerEntry>, String> {
    let markers = attributes
        .iter()
        .filter_map(|attribute| match &attribute.meta {
            Meta::NameValue(name_value) if attribute.path().is_ident("doc") => {
                let Expr::Lit(ExprLit {
                    lit: Lit::Str(value),
                    ..
                }) = &name_value.value
                else {
                    return None;
                };
                value
                    .value()
                    .trim_start()
                    .strip_prefix("mecmcp-compat: ")
                    .map(marker)
            }
            _ => None,
        })
        .collect::<Result<Vec<_>, _>>()?;
    match markers.as_slice() {
        [] => Ok(None),
        [marker] => Ok(Some(marker.clone())),
        _ => Err("multiple compatibility markers attached to one declaration".to_owned()),
    }
}

fn item_attributes(item: &Item) -> Option<&[Attribute]> {
    match item {
        Item::Const(item) => Some(&item.attrs),
        Item::Enum(item) => Some(&item.attrs),
        Item::ExternCrate(item) => Some(&item.attrs),
        Item::Fn(item) => Some(&item.attrs),
        Item::ForeignMod(item) => Some(&item.attrs),
        Item::Impl(item) => Some(&item.attrs),
        Item::Macro(item) => Some(&item.attrs),
        Item::Mod(item) => Some(&item.attrs),
        Item::Static(item) => Some(&item.attrs),
        Item::Struct(item) => Some(&item.attrs),
        Item::Trait(item) => Some(&item.attrs),
        Item::TraitAlias(item) => Some(&item.attrs),
        Item::Type(item) => Some(&item.attrs),
        Item::Union(item) => Some(&item.attrs),
        Item::Use(item) => Some(&item.attrs),
        Item::Verbatim(_) => None,
        _ => None,
    }
}

fn impl_item_attributes(item: &ImplItem) -> Option<&[Attribute]> {
    match item {
        ImplItem::Const(item) => Some(&item.attrs),
        ImplItem::Fn(item) => Some(&item.attrs),
        ImplItem::Type(item) => Some(&item.attrs),
        ImplItem::Macro(item) => Some(&item.attrs),
        ImplItem::Verbatim(_) => None,
        _ => None,
    }
}

fn count_markers(items: &[Item]) -> Result<usize, String> {
    let mut count = 0;
    for item in items {
        let Some(attributes) = item_attributes(item) else {
            continue;
        };
        if cfg_test(attributes) {
            continue;
        }
        count += usize::from(marker_attribute(attributes)?.is_some());
        match item {
            Item::Impl(item) => {
                for item in &item.items {
                    let Some(attributes) = impl_item_attributes(item) else {
                        continue;
                    };
                    if !cfg_test(attributes) {
                        count += usize::from(marker_attribute(attributes)?.is_some());
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    count += count_markers(items)?;
                }
            }
            _ => {}
        }
    }
    Ok(count)
}

fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn require_marker(
    attributes: &[Attribute],
    kind: &str,
    symbol_suffix: &str,
    path: &Path,
    markers: &mut Vec<LedgerEntry>,
) -> Result<(), String> {
    let marker = marker_attribute(attributes)?.ok_or_else(|| {
        format!(
            "unmarked {kind} declaration {symbol_suffix} in {}",
            path.display()
        )
    })?;
    if marker.0 != kind {
        return Err(format!(
            "marker kind {} does not match {kind} declaration {symbol_suffix} in {}",
            marker.0,
            path.display()
        ));
    }
    let symbol_matches = if kind == "method" {
        let mut marker_parts = marker.1.rsplit("::");
        let mut declaration_parts = symbol_suffix.rsplit("::");
        marker_parts.next() == declaration_parts.next()
            && marker_parts.next() == declaration_parts.next()
    } else {
        marker.1.rsplit("::").next() == Some(symbol_suffix.trim_start_matches("::"))
    };
    if !symbol_matches {
        return Err(format!(
            "marker symbol {} does not match declaration {symbol_suffix} in {}",
            marker.1,
            path.display()
        ));
    }
    markers.push(marker);
    Ok(())
}

fn scan_items(items: &[Item], path: &Path, markers: &mut Vec<LedgerEntry>) -> Result<(), String> {
    for item in items {
        match item {
            Item::Fn(item) if !cfg_test(&item.attrs) => require_marker(
                &item.attrs,
                "function",
                &format!("::{}", item.sig.ident),
                path,
                markers,
            )?,
            Item::Struct(item) if !cfg_test(&item.attrs) => require_marker(
                &item.attrs,
                "type",
                &format!("::{}", item.ident),
                path,
                markers,
            )?,
            Item::Enum(item) if !cfg_test(&item.attrs) => require_marker(
                &item.attrs,
                "type",
                &format!("::{}", item.ident),
                path,
                markers,
            )?,
            Item::Trait(item) if !cfg_test(&item.attrs) => require_marker(
                &item.attrs,
                "type",
                &format!("::{}", item.ident),
                path,
                markers,
            )?,
            Item::Type(item) if !cfg_test(&item.attrs) => require_marker(
                &item.attrs,
                "type",
                &format!("::{}", item.ident),
                path,
                markers,
            )?,
            Item::Impl(item) if !cfg_test(&item.attrs) => {
                let owner = type_name(&item.self_ty)
                    .ok_or_else(|| format!("unsupported impl type in {}", path.display()))?;
                for method in &item.items {
                    if let ImplItem::Fn(method) = method
                        && !cfg_test(&method.attrs)
                    {
                        require_marker(
                            &method.attrs,
                            "method",
                            &format!("{owner}::{}", method.sig.ident),
                            path,
                            markers,
                        )?;
                    }
                }
            }
            Item::Mod(module) if !cfg_test(&module.attrs) => {
                if let Some((_, items)) = &module.content {
                    scan_items(items, path, markers)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn scan_source(source: &str, path: &Path) -> Result<Vec<LedgerEntry>, String> {
    let file = syn::parse_file(source)
        .map_err(|error| format!("parse compatibility source {}: {error}", path.display()))?;
    let mut markers = Vec::new();
    scan_items(&file.items, path, &mut markers)?;
    if markers.len() != count_markers(&file.items)? {
        return Err(format!("orphan compatibility marker in {}", path.display()));
    }
    Ok(markers)
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
    let mut declaration_count = 0;
    for path in compatibility_sources() {
        let source = fs::read_to_string(&path).expect("read compatibility source");
        for entry in scan_source(&source, &path).expect("scan compatibility source") {
            declaration_count += 1;
            assert!(
                source_entries.insert(entry),
                "duplicate compatibility marker in {}",
                path.display(),
            );
        }
    }

    assert_eq!(
        declaration_count, 59,
        "source must contain exactly 59 declarations"
    );
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

#[test]
fn scanner_rejects_a_marker_bound_to_the_wrong_symbol() {
    let source = r#"
/// mecmcp-compat: type fixture::Wrong https://github.com/fastrevmd-lab/mecmcp/issues/1
pub struct Actual;
"#;
    let error = scan_source(source, Path::new("fixture.rs")).expect_err("wrong marker symbol");
    assert!(error.contains("fixture::Wrong"));
}

#[test]
fn scanner_rejects_unmarked_visibility_and_multiline_declarations() {
    let source = r#"
pub(super) struct Hidden;
pub(crate)
struct Multiline;
"#;
    let error = scan_source(source, Path::new("fixture.rs")).expect_err("unmarked declarations");
    assert!(error.contains("Hidden") || error.contains("Multiline"));
}

#[test]
fn scanner_rejects_a_method_marker_bound_to_the_wrong_impl_type() {
    let source = r#"
/// mecmcp-compat: type fixture::Owner https://github.com/fastrevmd-lab/mecmcp/issues/4
pub struct Owner;
impl Owner {
    /// mecmcp-compat: method fixture::NotOwner::run https://github.com/fastrevmd-lab/mecmcp/issues/3
    pub fn run() {}
}
"#;
    let error = scan_source(source, Path::new("fixture.rs")).expect_err("wrong impl owner");
    assert!(error.contains("NotOwner::run"));
}

#[test]
fn scanner_visits_nested_modules() {
    let source = r#"
mod nested {
    /// mecmcp-compat: type fixture::Nested https://github.com/fastrevmd-lab/mecmcp/issues/2
    pub struct Nested;
}
"#;
    let markers = scan_source(source, Path::new("fixture.rs")).expect("nested marker");
    assert_eq!(markers.len(), 1);
}

#[test]
fn scanner_ignores_cfg_test_modules() {
    let source = r#"
#[cfg(test)]
mod tests {
    /// mecmcp-compat: type fixture::TestOnly https://github.com/fastrevmd-lab/mecmcp/issues/5
    pub struct TestOnly;
}
/// mecmcp-compat: type fixture::Live https://github.com/fastrevmd-lab/mecmcp/issues/6
pub struct Live;
"#;
    let markers = scan_source(source, Path::new("fixture.rs")).expect("skip test module");
    assert_eq!(markers.len(), 1);
}
