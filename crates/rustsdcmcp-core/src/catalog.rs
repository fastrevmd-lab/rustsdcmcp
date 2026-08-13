//! Allowlisted generic resource catalogs, split by capability.
//!
//! [`ResourceKind`] lists every family this server may **read**.
//! [`WritableResource`] lists the far smaller set it may also **write**, and
//! converts into [`ResourceKind`] one way only. Exposing a family for reading
//! therefore cannot expose it for writing: there is no
//! `TryFrom<ResourceKind> for WritableResource`, and no runtime `writable()`
//! predicate a call site could forget to consult.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Uniform SDC resource collections this server may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Address objects.
    Addresses,
    /// Application objects.
    Applications,
    /// Service objects.
    Services,
    /// Scheduler objects.
    Schedulers,
}

impl ResourceKind {
    /// Every readable family, for exhaustive iteration in tests and tooling.
    pub const ALL: &'static [Self] = &[
        Self::Addresses,
        Self::Applications,
        Self::Services,
        Self::Schedulers,
    ];

    /// Exact collection path segments from the pinned OpenAPI document.
    #[must_use]
    pub const fn collection_segments(self) -> &'static [&'static str] {
        match self {
            Self::Addresses => &["api", "v1", "addresses"],
            Self::Applications => &["api", "v1", "applications"],
            Self::Services => &["api", "v1", "services"],
            Self::Schedulers => &["api", "v1", "schedulers"],
        }
    }
}

/// SDC resource collections this server may create, update, and delete.
///
/// Deliberately far narrower than [`ResourceKind`]. A family belongs here only
/// once its write path has been exercised against a live tenant; SDC is a
/// management plane, so an unvalidated write can move policy across an estate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WritableResource {
    /// Address objects.
    Addresses,
    /// Application objects.
    Applications,
    /// Service objects.
    Services,
    /// Scheduler objects.
    Schedulers,
}

impl WritableResource {
    /// Every writable family, for exhaustive iteration in tests and tooling.
    pub const ALL: &'static [Self] = &[
        Self::Addresses,
        Self::Applications,
        Self::Services,
        Self::Schedulers,
    ];

    /// Exact collection path segments, delegated to the read catalog.
    ///
    /// Delegating keeps one table authoritative: a writable family cannot
    /// drift onto a different path from the read used to detect drift on it.
    #[must_use]
    pub const fn collection_segments(self) -> &'static [&'static str] {
        ResourceKind::from_writable(self).collection_segments()
    }
}

impl ResourceKind {
    /// Widen a writable family to its readable counterpart.
    ///
    /// A `const fn` because [`WritableResource::collection_segments`] is
    /// `const`; [`From`] is not usable in const context.
    #[must_use]
    pub const fn from_writable(resource: WritableResource) -> Self {
        match resource {
            WritableResource::Addresses => Self::Addresses,
            WritableResource::Applications => Self::Applications,
            WritableResource::Services => Self::Services,
            WritableResource::Schedulers => Self::Schedulers,
        }
    }
}

impl From<WritableResource> for ResourceKind {
    fn from(resource: WritableResource) -> Self {
        Self::from_writable(resource)
    }
}

#[cfg(test)]
mod tests {
    use super::{ResourceKind, WritableResource};
    use serde_json::json;

    /// Every writable family must also be readable.
    ///
    /// The conversion is one-way by construction, but this pins that it
    /// resolves to the *same* collection — a write and its drift-detection
    /// read must never address different paths.
    #[test]
    fn every_writable_family_reads_from_the_same_collection() {
        for writable in WritableResource::ALL {
            let readable = ResourceKind::from(*writable);
            assert_eq!(
                writable.collection_segments(),
                readable.collection_segments(),
                "{writable:?} writes and reads different collections"
            );
        }
    }

    /// The write catalog is deliberately four families wide.
    ///
    /// Widening it is a decision, not a side effect of widening reads, so it
    /// must fail here first.
    #[test]
    fn the_write_catalog_stays_at_four_families() {
        assert_eq!(WritableResource::ALL.len(), 4);
    }

    /// `WritableResource` serialises identically to `ResourceKind`.
    ///
    /// `plan_artifact` embeds the resource in the digested plan, and prepared
    /// object writes are persisted in `changeset-state.json`. A different wire
    /// name would change every digest and orphan every persisted change set.
    #[test]
    fn the_two_catalogs_agree_on_wire_names() {
        for writable in WritableResource::ALL {
            let readable = ResourceKind::from(*writable);
            assert_eq!(
                json!(writable),
                json!(readable),
                "{writable:?} changed its serialised name"
            );
        }
        assert_eq!(json!(WritableResource::Addresses), json!("addresses"));
    }
}
