//! Allowlisted generic read-only resource catalog.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Uniform read-only SDC resource collections exposed by generic tools.
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
