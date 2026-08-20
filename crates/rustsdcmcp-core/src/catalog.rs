//! Allowlisted generic resource catalogs, split by capability.
//!
//! [`ResourceKind`] lists every family this server may **read**.
//! [`WritableResource`] lists the far smaller set it may also **write**, and
//! converts into [`ResourceKind`] one way only. Exposing a family for reading
//! therefore cannot expose it for writing: there is no
//! `TryFrom<ResourceKind> for WritableResource`, and no runtime `writable()`
//! predicate a call site could forget to consult.
//!
//! Families deliberately absent, and why — so an absence is not rediscovered as
//! an oversight. Two reasons recur, and everything below is one of them.
//!
//! **Not expressible as a flat collection path.** A `&'static [&'static str]`
//! addresses `/api/v1/<collection>` and nothing deeper.
//!
//! - `IPSRule`, `IPSExemptRule` — `/api/v1/ips_profiles/{profile_uuid}/…`
//! - `EnhancedContentFilteringProfileSet` —
//!   `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets`,
//!   and its rules are two levels deeper again
//!
//! **Not boundable.** The collection GET accepts neither `from` nor `fields`,
//! so a response cannot be limited, and bounding is not optional here.
//!
//! - `DeviceGlobalSettings` — `/api/v1/firewall_device_global_settings`
//! - `GlobalProfile` — `/api/v1/firewall_global_profiles`, a singleton `GET`
//! - `GlobalSettings` — `/api/v1/firewall_global_settings`, a singleton `GET`
//! - `ContentSecuritySettings` — `/api/v1/content_security_settings`, a
//!   singleton `GET` rather than a list
//!
//! **Bespoke tools instead.** `NAT Pools` is keyed by `pool_id`; `Device
//! Groups` needs membership, which the generic shape cannot return.

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
    /// Advanced anti-malware profiles.
    AamwProfiles,
    /// Anti-spam profiles.
    AntiSpamProfiles,
    /// Anti-virus profiles.
    AntiVirusProfiles,
    /// Content-filtering profiles.
    ContentFilteringProfiles,
    /// Content-security profiles.
    ContentSecurityProfiles,
    /// Enhanced content-filtering profiles.
    EnhancedContentFilteringProfiles,
    /// Flow-based antivirus profiles.
    FlowBasedAntivirusProfiles,
    /// ICAP profiles.
    IcapProfiles,
    /// ICAP servers.
    IcapServers,
    /// Identity objects.
    IdentityObjects,
    /// IPS contexts.
    IpsContexts,
    /// IPS profiles.
    IpsProfiles,
    /// IPS services.
    IpsServices,
    /// IPS signatures.
    IpsSignatures,
    /// IPS vulnerabilities.
    IpsVulnerabilities,
    /// Proxy servers.
    ProxyServers,
    /// Redirect profiles.
    RedirectProfiles,
    /// Rule options, referenced by `options.logging` and `options.counter`.
    RuleOptions,
    /// Security-intelligence profiles.
    SecintelProfiles,
    /// Security-intelligence profile groups.
    SecintelProfilesGroups,
    /// SSL initiation profiles.
    SslInitiations,
    /// SSL proxy profiles.
    SslProxyProfiles,
    /// Secure web proxy profiles.
    SwpProfiles,
    /// URL category lists.
    UrlCategoryLists,
    /// URL patterns.
    UrlPatterns,
    /// Configuration templates.
    ///
    /// Read-only on purpose. A template applies to every device mapped to it,
    /// so a write is estate-scale rather than device-scale — the blast radius
    /// rustsdcmcp#33 raises. It is absent from [`WritableResource`], and the
    /// one-way conversion means that cannot be undone by omission.
    Templates,
    /// Variable zones, referenced by `ZoneReference.managed_variable`.
    VariableZones,
    /// Web-filtering profiles.
    WebFilteringProfiles,
}

impl ResourceKind {
    /// Every readable family, for exhaustive iteration in tests and tooling.
    pub const ALL: &'static [Self] = &[
        Self::Addresses,
        Self::Applications,
        Self::Services,
        Self::Schedulers,
        Self::AamwProfiles,
        Self::AntiSpamProfiles,
        Self::AntiVirusProfiles,
        Self::ContentFilteringProfiles,
        Self::ContentSecurityProfiles,
        Self::EnhancedContentFilteringProfiles,
        Self::FlowBasedAntivirusProfiles,
        Self::IcapProfiles,
        Self::IcapServers,
        Self::IdentityObjects,
        Self::IpsContexts,
        Self::IpsProfiles,
        Self::IpsServices,
        Self::IpsSignatures,
        Self::IpsVulnerabilities,
        Self::ProxyServers,
        Self::RedirectProfiles,
        Self::RuleOptions,
        Self::SecintelProfiles,
        Self::SecintelProfilesGroups,
        Self::SslInitiations,
        Self::SslProxyProfiles,
        Self::SwpProfiles,
        Self::UrlCategoryLists,
        Self::UrlPatterns,
        Self::Templates,
        Self::VariableZones,
        Self::WebFilteringProfiles,
    ];

    /// Exact collection path segments from the pinned OpenAPI document.
    #[must_use]
    pub const fn collection_segments(self) -> &'static [&'static str] {
        match self {
            Self::Addresses => &["api", "v1", "addresses"],
            Self::Applications => &["api", "v1", "applications"],
            Self::Services => &["api", "v1", "services"],
            Self::Schedulers => &["api", "v1", "schedulers"],
            Self::AamwProfiles => &["api", "v1", "aamw_profiles"],
            Self::AntiSpamProfiles => &["api", "v1", "anti_spam_profiles"],
            Self::AntiVirusProfiles => &["api", "v1", "anti_virus_profiles"],
            Self::ContentFilteringProfiles => &["api", "v1", "content_filtering_profiles"],
            Self::ContentSecurityProfiles => &["api", "v1", "content_security_profiles"],
            Self::EnhancedContentFilteringProfiles => {
                &["api", "v1", "enhanced_content_filtering_profiles"]
            }
            Self::FlowBasedAntivirusProfiles => &["api", "v1", "flow_based_antivirus_profiles"],
            Self::IcapProfiles => &["api", "v1", "icap_profiles"],
            Self::IcapServers => &["api", "v1", "icap_servers"],
            Self::IdentityObjects => &["api", "v1", "identity_objects"],
            Self::IpsContexts => &["api", "v1", "ips_contexts"],
            Self::IpsProfiles => &["api", "v1", "ips_profiles"],
            Self::IpsServices => &["api", "v1", "ips_services"],
            Self::IpsSignatures => &["api", "v1", "ips_signatures"],
            Self::IpsVulnerabilities => &["api", "v1", "ips_vulnerabilities"],
            Self::ProxyServers => &["api", "v1", "proxy_servers"],
            Self::RedirectProfiles => &["api", "v1", "redirect_profiles"],
            Self::RuleOptions => &["api", "v1", "rule_options"],
            Self::SecintelProfiles => &["api", "v1", "secintel_profiles"],
            Self::SecintelProfilesGroups => &["api", "v1", "secintel_profiles_groups"],
            Self::SslInitiations => &["api", "v1", "ssl_initiations"],
            Self::SslProxyProfiles => &["api", "v1", "ssl_proxy_profiles"],
            Self::SwpProfiles => &["api", "v1", "swp_profiles"],
            Self::UrlCategoryLists => &["api", "v1", "url_category_lists"],
            Self::UrlPatterns => &["api", "v1", "url_patterns"],
            Self::Templates => &["api", "v1", "templates"],
            Self::VariableZones => &["api", "v1", "variable_zones"],
            Self::WebFilteringProfiles => &["api", "v1", "web_filtering_profiles"],
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

    /// Every readable family's wire name is its own collection segment.
    ///
    /// The catalog is 27 hand-transcribed paths. This turns a transposed or
    /// misspelled path into a test failure instead of a 404 against a live
    /// tenant, because the variant name and the path are checked against each
    /// other rather than both against the author's memory.
    #[test]
    fn every_readable_family_is_named_after_its_collection() {
        for kind in ResourceKind::ALL {
            let segments = kind.collection_segments();
            assert_eq!(
                &segments[..2],
                &["api", "v1"],
                "{kind:?} is not a /api/v1/ collection"
            );
            assert_eq!(segments.len(), 3, "{kind:?} has an unexpected path depth");
            let wire = json!(kind);
            assert_eq!(
                wire.as_str(),
                Some(segments[2]),
                "{kind:?} serialises to {wire} but reads {}",
                segments[2]
            );
        }
    }

    /// `ALL` must not fall behind the enum.
    ///
    /// `schemars` derives the variant list from the type itself, so a variant
    /// added without a matching `ALL` entry fails here. Without this, the two
    /// invariant tests above would silently stop covering the new family --
    /// and the JSON schema is also the client-facing catalog, so the two must
    /// agree for discovery to work at all.
    #[test]
    fn all_covers_every_variant_of_both_catalogs() {
        // schemars 1 renders a unit-only enum as a `oneOf` of one-`const`
        // string subschemas, each carrying the serde-renamed variant name.
        fn schema_names(schema: &serde_json::Value) -> Vec<String> {
            schema["oneOf"]
                .as_array()
                .expect("unit enum renders as a oneOf")
                .iter()
                .map(|variant| {
                    variant["const"]
                        .as_str()
                        .expect("each variant is a const string")
                        .to_owned()
                })
                .collect()
        }

        let read =
            serde_json::to_value(schemars::schema_for!(ResourceKind)).expect("schema serialises");
        let listed: Vec<String> = ResourceKind::ALL
            .iter()
            .map(|kind| json!(kind).as_str().expect("string").to_owned())
            .collect();
        assert_eq!(schema_names(&read), listed);

        let write = serde_json::to_value(schemars::schema_for!(WritableResource))
            .expect("schema serialises");
        let listed: Vec<String> = WritableResource::ALL
            .iter()
            .map(|kind| json!(kind).as_str().expect("string").to_owned())
            .collect();
        assert_eq!(schema_names(&write), listed);
    }

    /// The read catalog covers the uniform five-operation families.
    #[test]
    fn the_read_catalog_covers_thirty_two_families() {
        assert_eq!(ResourceKind::ALL.len(), 32);
    }

    /// Templates are readable and **not** writable, and that is structural
    /// rather than a policy anyone can forget.
    ///
    /// A template applies across every device mapped to it, so a write is
    /// estate-scale — the blast radius rustsdcmcp#33 flags. Because
    /// `WritableResource` converts into `ResourceKind` one way only, a family
    /// present in the read catalog cannot be written unless someone adds it to
    /// the write catalog on purpose.
    #[test]
    fn templates_are_readable_but_not_writable() {
        assert!(
            ResourceKind::ALL.contains(&ResourceKind::Templates),
            "templates must be readable"
        );
        assert!(
            !WritableResource::ALL
                .iter()
                .any(|writable| ResourceKind::from_writable(*writable) == ResourceKind::Templates),
            "a template write is estate-scale and must not be reachable through \
             the generic write path"
        );
    }
}
