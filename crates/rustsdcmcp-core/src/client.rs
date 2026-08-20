//! Bounded SDC HTTPS client.
//!
//! The product-specific implementation here is intentionally isolated while
//! its reusable foundations are tracked in mecmcp issue #90.

use crate::{
    DeployRequest, DeploymentStatus, JobStatus, ListRequest, ListRequestError, PolicyOperation,
    PreviewRequest, ResourceKind, SdcConfig, SdcPreparedChange, SdcPreparedTarget, TenantScope,
    WritableResource,
    models::{DeployResponse, PreviewResponse},
};
use futures::StreamExt as _;
use reqwest::{Method, StatusCode, header::HeaderValue};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{self, Instant},
};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

struct Credential(Zeroizing<String>);

impl std::fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Credential([REDACTED])")
    }
}

/// Cloneable, bounded client for one SDC tenant.
#[derive(Clone)]
pub struct SdcClient {
    http: reqwest::Client,
    base_url: Url,
    credential: Arc<Credential>,
    auth_scheme: crate::AuthScheme,
    request_timeout: Duration,
    max_response_bytes: usize,
    concurrency: Arc<Semaphore>,
    poll: crate::config::PollSettings,
    max_page_size: u32,
    shutdown: CancellationToken,
}

impl std::fmt::Debug for SdcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SdcClient")
            .field("base_url", &self.base_url)
            .field("credential", &self.credential)
            .field("auth_scheme", &self.auth_scheme)
            .field("request_timeout", &self.request_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_page_size", &self.max_page_size)
            .finish_non_exhaustive()
    }
}

impl SdcClient {
    /// Build a production HTTPS-only client from a separately resolved credential.
    ///
    /// The consuming binary must install a rustls crypto provider first.
    ///
    /// # Errors
    ///
    /// Returns stable, credential-free configuration or client-construction errors.
    pub fn new(config: &SdcConfig, credential: String) -> Result<Self, SdcError> {
        config
            .validate()
            .map_err(|error| SdcError::Config(error.to_string()))?;
        if credential.is_empty() || credential.len() > 16 * 1024 {
            return Err(SdcError::Credential);
        }
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(config.max_concurrency)
            .user_agent(format!("rustsdcmcp/{}", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            .build()
            .map_err(|_| SdcError::ClientConstruction)?;
        Self::from_parts(config, credential, http)
    }

    fn from_parts(
        config: &SdcConfig,
        credential: String,
        http: reqwest::Client,
    ) -> Result<Self, SdcError> {
        Ok(Self {
            http,
            base_url: config
                .base_url()
                .map_err(|error| SdcError::Config(error.to_string()))?,
            credential: Arc::new(Credential(Zeroizing::new(credential))),
            auth_scheme: config.auth_scheme,
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            max_response_bytes: config.max_response_bytes,
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
            poll: config
                .poll_settings()
                .map_err(|error| SdcError::Config(error.to_string()))?,
            max_page_size: config.max_page_size,
            shutdown: CancellationToken::new(),
        })
    }

    /// Bind this client to a process-wide shutdown signal.
    ///
    /// Every request and job poll then aborts when the process begins shutting
    /// down, instead of holding a listener drain open for the remainder of
    /// `poll_deadline_ms`. A client built without one carries a token that is
    /// never cancelled.
    #[must_use]
    pub fn with_shutdown(mut self, shutdown: CancellationToken) -> Self {
        self.shutdown = shutdown;
        self
    }

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        base_url: Url,
        credential: String,
        max_response_bytes: usize,
        max_page_size: u32,
    ) -> Self {
        let config = SdcConfig {
            version: 1,
            tenant: "test".to_owned(),
            expected_tenant_id: "tenant-test".to_owned(),
            credential_env: "TEST_SDC_TOKEN".to_owned(),
            auth_scheme: crate::AuthScheme::ApiKey,
            endpoint: "https://example.invalid/".to_owned(),
            connect_timeout_ms: 1_000,
            request_timeout_ms: 2_000,
            max_response_bytes,
            max_concurrency: 2,
            max_page_size,
            poll_initial_ms: 1,
            poll_max_ms: 2,
            poll_deadline_ms: 50,
            changeset_state_file: None,
            approval_ttl_secs: 60,
        };
        let mut client =
            Self::from_parts(&config, credential, reqwest::Client::new()).expect("test client");
        client.base_url = base_url;
        client
    }

    /// Maximum page size allowed by this tenant configuration.
    #[must_use]
    pub const fn max_page_size(&self) -> u32 {
        self.max_page_size
    }

    /// Fetch the credential tenant scope.
    pub async fn tenant_scope(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<TenantScope, SdcError> {
        self.get(&["api", "v2", "tenant", "tenant-id"], &[], cancellation)
            .await
    }

    /// Verify that a credential resolves to the configured tenant ID.
    pub async fn verify_tenant(
        &self,
        expected_tenant_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<TenantScope, SdcError> {
        let scope = self.tenant_scope(cancellation).await?;
        if scope.tenant_id != expected_tenant_id {
            return Err(SdcError::TenantMismatch);
        }
        Ok(scope)
    }

    /// List managed devices with bounded pagination.
    pub async fn list_devices(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "devices"], page, cancellation)
            .await
    }

    /// Create a new firewall policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is not a bounded JSON object, or when
    /// the SDC request fails.
    pub async fn create_firewall_policy(
        &self,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "firewall"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Replace an existing firewall policy by UUID.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID or body is invalid, or when the SDC
    /// request fails.
    pub async fn update_firewall_policy(
        &self,
        uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &["api", "v1", "policies", "firewall", uuid],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Delete an existing firewall policy by UUID.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid or when the SDC request
    /// fails.
    pub async fn delete_firewall_policy(
        &self,
        uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        self.send_write(
            Method::DELETE,
            &["api", "v1", "policies", "firewall", uuid],
            None,
            cancellation,
        )
        .await
    }

    /// Fetch the operational state of a firewall policy by UUID.
    ///
    /// Returns policy deployment state and optionally per-device states when
    /// `include_assigned_devices` is true.
    pub async fn get_firewall_policy_state(
        &self,
        policy_uuid: &str,
        include_assigned_devices: bool,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        let query = if include_assigned_devices {
            vec![("include_assigned_devices", "true")]
        } else {
            vec![]
        };
        self.get(
            &["api", "v1", "policies", "firewall", policy_uuid, "state"],
            &query,
            cancellation,
        )
        .await
    }

    /// List NAT pools with bounded pagination.
    pub async fn list_nat_pools(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "nat_pools"], page, cancellation)
            .await
    }

    /// List device groups with bounded pagination and an optional projection.
    ///
    /// A group embeds its membership, so `size` alone does not bound the
    /// response: one large group can exceed `max_response_bytes` and refuse
    /// the read. Pass `fields` to project the response down to group metadata
    /// and use [`Self::get_device_group`] when membership is actually wanted.
    ///
    /// The field names are the API's, not this crate's, and no default
    /// projection is applied: guessing them would silently drop data. The lab
    /// tenant has no groups, so none has been observed to hard-code.
    pub async fn list_device_groups(
        &self,
        page: ListRequest,
        fields: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_projected(&["api", "v1", "device_groups"], page, fields, cancellation)
            .await
    }

    /// Fetch one device group by UUID, including its membership.
    pub async fn get_device_group(
        &self,
        group_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("group_uuid", group_uuid)?;
        self.get(
            &["api", "v1", "device_groups", group_uuid],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch one NAT pool by ID.
    ///
    /// NAT resources use a numeric-string `id`, not the UUID the firewall side
    /// uses — see docs/sdc-api/README.md.
    pub async fn get_nat_pool(
        &self,
        pool_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("pool_id", pool_id)?;
        self.get(&["api", "v1", "nat_pools", pool_id], &[], cancellation)
            .await
    }

    /// Fetch one managed device by UUID.
    pub async fn get_device(
        &self,
        device_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.get(&["api", "v1", "devices", device_uuid], &[], cancellation)
            .await
    }

    /// List configuration versions for one device.
    ///
    /// Returns the standard `{"items": [...], "count": N}` envelope with archived
    /// configuration metadata. The endpoint declares no pagination parameters, so
    /// the response is bounded only by `max_response_bytes`. A device with a long
    /// archive may exceed that limit and fail the read.
    pub async fn list_config_versions(
        &self,
        device_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.get(
            &["api", "v1", "devices", device_uuid, "config", "versions"],
            &[],
            cancellation,
        )
        .await
    }

    /// List firewall policies with bounded pagination.
    pub async fn list_firewall_policies(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "policies", "firewall"], page, cancellation)
            .await
    }

    /// Fetch one firewall policy by UUID.
    pub async fn get_firewall_policy(
        &self,
        policy_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        self.get(
            &["api", "v1", "policies", "firewall", policy_uuid],
            &[],
            cancellation,
        )
        .await
    }

    /// List NAT policies with bounded pagination.
    pub async fn list_nat_policies(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v1", "policies", "nat"], page, cancellation)
            .await
    }

    /// Fetch one NAT policy by ID.
    pub async fn get_nat_policy(
        &self,
        id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("id", id)?;
        self.get(&["api", "v1", "policies", "nat", id], &[], cancellation)
            .await
    }

    /// List firewall policy rules with bounded pagination.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    pub async fn list_firewall_rules(
        &self,
        policy_uuid: &str,
        scope: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        self.list(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "rules",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one firewall policy rule by UUID.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    pub async fn get_firewall_rule(
        &self,
        policy_uuid: &str,
        scope: &str,
        rule_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        validate_atom("rule_uuid", rule_uuid)?;
        self.get(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "rules",
                rule_uuid,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// List firewall policy rule groups with bounded pagination.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    pub async fn list_firewall_rule_groups(
        &self,
        policy_uuid: &str,
        scope: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        self.list(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "rule_groups",
            ],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch firewall policy rule hierarchy.
    ///
    /// `scope` must be `"global"` or `"zone"`.
    ///
    /// Note: The spec misspells this path segment as `heirarchy`.
    pub async fn get_firewall_hierarchy(
        &self,
        policy_uuid: &str,
        scope: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_uuid", policy_uuid)?;
        validate_atom("scope", scope)?;
        self.get(
            &[
                "api",
                "v1",
                "policies",
                "firewall",
                policy_uuid,
                scope,
                "heirarchy",
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// List NAT policy rules with bounded pagination.
    pub async fn list_nat_rules(
        &self,
        policy_id: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.list(
            &["api", "v1", "policies", "nat", policy_id, "rules"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one NAT policy rule by ID.
    pub async fn get_nat_rule(
        &self,
        policy_id: &str,
        rule_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("rule_id", rule_id)?;
        self.get(
            &["api", "v1", "policies", "nat", policy_id, "rules", rule_id],
            &[],
            cancellation,
        )
        .await
    }

    /// List NAT policy rule groups with bounded pagination.
    pub async fn list_nat_rule_groups(
        &self,
        policy_id: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.list(
            &["api", "v1", "policies", "nat", policy_id, "rule_groups"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch NAT policy rule hierarchy.
    ///
    /// Note: Unlike firewall policies, NAT uses the correctly-spelled `hierarchy`.
    pub async fn get_nat_hierarchy(
        &self,
        policy_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.get(
            &["api", "v1", "policies", "nat", policy_id, "hierarchy"],
            &[],
            cancellation,
        )
        .await
    }

    /// List one allowlisted generic resource family.
    ///
    /// `size` bounds how many objects come back, not how large each one is,
    /// and profile families embed rule and pattern lists. Pass `fields` to
    /// apply the API's server-side projection; pass an empty slice to omit the
    /// parameter entirely. No default projection is invented — field names
    /// belong to the API, and guessing them silently drops data.
    pub async fn list_resource(
        &self,
        kind: ResourceKind,
        page: ListRequest,
        fields: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_projected(kind.collection_segments(), page, fields, cancellation)
            .await
    }

    /// Fetch one allowlisted generic resource by UUID.
    pub async fn get_resource(
        &self,
        kind: ResourceKind,
        uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        let mut segments = kind.collection_segments().to_vec();
        segments.push(uuid);
        self.get(&segments, &[], cancellation).await
    }

    /// Create one object in an allowlisted generic resource family.
    ///
    /// Takes [`WritableResource`], not [`ResourceKind`]: adding a family to the
    /// read catalog must not make it writable.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is not a bounded JSON object, or when
    /// the SDC request fails.
    pub async fn create_resource(
        &self,
        kind: WritableResource,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            kind.collection_segments(),
            Some(body),
            cancellation,
        )
        .await
    }

    /// Replace one object in an allowlisted generic resource family.
    ///
    /// Takes [`WritableResource`], not [`ResourceKind`]: adding a family to the
    /// read catalog must not make it writable.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID or body is invalid, or when the SDC
    /// request fails.
    pub async fn update_resource(
        &self,
        kind: WritableResource,
        uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        validate_object_body(body)?;
        let mut segments = kind.collection_segments().to_vec();
        segments.push(uuid);
        self.send_write(Method::PUT, &segments, Some(body), cancellation)
            .await
    }

    /// Delete one object from an allowlisted generic resource family.
    ///
    /// Takes [`WritableResource`], not [`ResourceKind`]: adding a family to the
    /// read catalog must not make it writable.
    ///
    /// # Errors
    ///
    /// Returns an error when the UUID is invalid or when the SDC request
    /// fails. SDC rejects deleting an object that a policy still references.
    pub async fn delete_resource(
        &self,
        kind: WritableResource,
        uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("uuid", uuid)?;
        let mut segments = kind.collection_segments().to_vec();
        segments.push(uuid);
        self.send_write(Method::DELETE, &segments, None, cancellation)
            .await
    }

    /// List IPsec profiles with bounded pagination.
    ///
    /// This is a `/api/v2/` endpoint, unlike most policy and device operations.
    pub async fn list_ipsec_profiles(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v2", "ipsec-profiles"], page, cancellation)
            .await
    }

    /// Fetch one IPsec profile by name.
    ///
    /// IPsec profiles are addressed by `profile_name`, not UUID or numeric ID.
    /// This is a `/api/v2/` endpoint.
    pub async fn get_ipsec_profile(
        &self,
        profile_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_name", profile_name)?;
        self.get(
            &["api", "v2", "ipsec-profile", profile_name],
            &[],
            cancellation,
        )
        .await
    }

    /// List tunnels with bounded pagination.
    ///
    /// This is a `/api/v2/` endpoint. Tunnels are read-only derived state,
    /// not directly created or deleted.
    pub async fn list_tunnels(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(&["api", "v2", "tunnels"], page, cancellation)
            .await
    }

    /// Fetch one tunnel by ID.
    ///
    /// This is a `/api/v2/` endpoint.
    pub async fn get_tunnel(
        &self,
        tunnel_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("tunnel_id", tunnel_id)?;
        self.get(&["api", "v2", "tunnel", tunnel_id], &[], cancellation)
            .await
    }

    /// Get tunnel status count.
    ///
    /// This is a `/api/v2/` endpoint.
    pub async fn tunnel_count(&self, cancellation: &CancellationToken) -> Result<Value, SdcError> {
        self.get(
            &["api", "v2", "tunnels", "status", "count"],
            &[],
            cancellation,
        )
        .await
    }

    /// List CA certificates across all devices with bounded pagination.
    pub async fn list_ca_certificates(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(
            &["api", "v1", "devices", "ca_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List local certificates across all devices with bounded pagination.
    pub async fn list_local_certificates(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(
            &["api", "v1", "devices", "local_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List CA certificates for one device with bounded pagination.
    pub async fn list_device_ca_certificates(
        &self,
        device_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.list(
            &["api", "v1", "devices", device_uuid, "ca_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List local certificates for one device with bounded pagination.
    pub async fn list_device_local_certificates(
        &self,
        device_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.list(
            &["api", "v1", "devices", device_uuid, "local_certificates"],
            page,
            cancellation,
        )
        .await
    }

    /// List licenses for one device with bounded pagination.
    pub async fn list_licenses(
        &self,
        device_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        self.list(
            &["api", "v1", "devices", device_uuid, "licenses"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one license by device UUID and license UUID.
    pub async fn get_license(
        &self,
        device_uuid: &str,
        license_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_atom("license_uuid", license_uuid)?;
        self.get(
            &[
                "api",
                "v1",
                "devices",
                device_uuid,
                "licenses",
                license_uuid,
            ],
            &[],
            cancellation,
        )
        .await
    }

    /// Install a license on a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn install_license(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &["api", "v1", "devices", device_uuid, "install_license"],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "install_license response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::InstallLicense, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Install a CA certificate on a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn install_ca_certificate(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &[
                    "api",
                    "v1",
                    "devices",
                    device_uuid,
                    "install_ca_certificate",
                ],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "install_ca_certificate response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::InstallCaCertificate, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Install a local certificate on a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn install_local_certificate(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &[
                    "api",
                    "v1",
                    "devices",
                    device_uuid,
                    "install_local_certificate",
                ],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "install_local_certificate response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::InstallLocalCertificate, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Delete a certificate from a device and poll until the operation completes.
    ///
    /// # Errors
    ///
    /// Returns an error when the device_uuid or body is invalid, or when the
    /// SDC request or polling fails.
    pub async fn delete_certificate(
        &self,
        device_uuid: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<(String, DeploymentStatus), SdcError> {
        validate_atom("device_uuid", device_uuid)?;
        validate_object_body(body)?;
        let response_value = self
            .send_write(
                Method::POST,
                &["api", "v1", "devices", device_uuid, "delete_certificate"],
                Some(body),
                cancellation,
            )
            .await?;
        let response: JobStatus =
            serde_json::from_value(response_value).map_err(|_| SdcError::Serialization)?;
        let job_id = response
            .deploy_id
            .as_ref()
            .ok_or(SdcError::InvalidInput(
                "delete_certificate response missing job id",
            ))?
            .clone();
        validate_atom("job_id", &job_id)?;
        let status = self
            .poll_job(JobKind::DeleteCertificate, &job_id, cancellation)
            .await?;
        Ok((job_id, status.status))
    }

    /// Read an install_license job status without polling.
    pub async fn install_license_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "install_license", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Ask SDC to re-read one or more devices' running configuration.
    ///
    /// **Direction: import.** `BulkSyncDevices` reads the device and updates
    /// SDC's model to match; it does not push SDC's view down. Confirmed
    /// against `vsrx-ci` on the live tenant (snapshot-gated, single device):
    /// the device's commit log was unchanged across the sync. The OpenAPI spec
    /// states no direction, which is why the finding is recorded in
    /// `docs/sdc-api/README.md` §5 and repeated here — this is the one property
    /// of this call that decides whether it is safe.
    ///
    /// Asynchronous: returns a `sync_id`, which this polls to completion.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or malformed UUID list, a rejected
    /// request, or a job that does not finish within the poll deadline.
    pub async fn sync_devices(
        &self,
        device_uuids: &[String],
        cancellation: &CancellationToken,
    ) -> Result<(String, crate::DeviceSyncStatus), SdcError> {
        if device_uuids.is_empty() {
            return Err(SdcError::InvalidInput(
                "device sync requires at least one device UUID",
            ));
        }
        for uuid in device_uuids {
            validate_atom("device_uuid", uuid)?;
        }
        let body = serde_json::json!({ "uuids": device_uuids });
        let response_value = self
            .send_write(
                Method::POST,
                &["api", "v1", "devices", "sync"],
                Some(&body),
                cancellation,
            )
            .await?;
        let sync_id = response_value
            .get("sync_id")
            .and_then(Value::as_str)
            .ok_or(SdcError::InvalidInput(
                "device sync response missing sync_id",
            ))?
            .to_owned();
        validate_atom("sync_id", &sync_id)?;
        // Polled here rather than through `poll_job`: this endpoint answers
        // `SUCCESS`/`FAILURE`, which `DeploymentStatus` does not recognise, so
        // the shared loop would never see a terminal state and every sync would
        // end in `JobDeadline` however well it went.
        //
        // The `sync_id` is returned alongside every error after this point, so a
        // caller that cannot learn the outcome can still name the job to an
        // operator.
        let status = self.poll_device_sync(&sync_id, cancellation).await?;
        Ok((sync_id, status))
    }

    /// Poll one device inventory sync to a terminal state.
    async fn poll_device_sync(
        &self,
        sync_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<crate::DeviceSyncStatus, SdcError> {
        let deadline = Instant::now() + self.poll.deadline;
        let mut interval = self.poll.initial;
        loop {
            let probe = self.sync_devices_status(sync_id, cancellation);
            let job = tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                result = probe => result?,
            };
            if job.status.is_terminal() {
                return Ok(job.status);
            }
            tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                () = time::sleep(interval) => {}
            }
            interval = interval.saturating_mul(2).min(self.poll.maximum);
        }
    }

    /// Read a device-sync job status without polling.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed sync id or an unreadable response.
    pub async fn sync_devices_status(
        &self,
        sync_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<crate::DeviceSyncJob, SdcError> {
        validate_atom("sync_id", sync_id)?;
        self.get(
            &["api", "v1", "devices", "sync", sync_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read an install_ca_certificate job status without polling.
    pub async fn install_ca_certificate_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "install_ca_certificate", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read an install_local_certificate job status without polling.
    pub async fn install_local_certificate_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "install_local_certificate", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read a delete_certificate job status without polling.
    pub async fn delete_certificate_status(
        &self,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("job_id", job_id)?;
        self.get(
            &["api", "v1", "devices", "delete_certificate", job_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Create a new NAT policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is invalid or when the SDC request fails.
    pub async fn create_nat_policy(
        &self,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "nat"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Update an existing NAT policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or body is invalid, or when the SDC
    /// request fails.
    pub async fn update_nat_policy(
        &self,
        policy_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &["api", "v1", "policies", "nat", policy_id],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Delete a NAT policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id is invalid or when the SDC request
    /// fails.
    pub async fn delete_nat_policy(
        &self,
        policy_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        self.send_write(
            Method::DELETE,
            &["api", "v1", "policies", "nat", policy_id],
            None,
            cancellation,
        )
        .await
    }

    /// Create a new NAT rule within a policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or body is invalid, or when the SDC
    /// request fails.
    pub async fn create_nat_rule(
        &self,
        policy_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "nat", policy_id, "rules"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Update an existing NAT rule.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id, rule_id, or body is invalid, or
    /// when the SDC request fails.
    pub async fn update_nat_rule(
        &self,
        policy_id: &str,
        rule_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("rule_id", rule_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &["api", "v1", "policies", "nat", policy_id, "rules", rule_id],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Delete a NAT rule.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or rule_id is invalid, or when the
    /// SDC request fails.
    pub async fn delete_nat_rule(
        &self,
        policy_id: &str,
        rule_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("rule_id", rule_id)?;
        self.send_write(
            Method::DELETE,
            &["api", "v1", "policies", "nat", policy_id, "rules", rule_id],
            None,
            cancellation,
        )
        .await
    }

    /// Create a new NAT rule group within a policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id or body is invalid, or when the SDC
    /// request fails.
    pub async fn create_nat_rule_group(
        &self,
        policy_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::POST,
            &["api", "v1", "policies", "nat", policy_id, "rule_groups"],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Update an existing NAT rule group.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy_id, group_id, or body is invalid, or
    /// when the SDC request fails.
    pub async fn update_nat_rule_group(
        &self,
        policy_id: &str,
        group_id: &str,
        body: &Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("policy_id", policy_id)?;
        validate_atom("group_id", group_id)?;
        validate_object_body(body)?;
        self.send_write(
            Method::PUT,
            &[
                "api",
                "v1",
                "policies",
                "nat",
                policy_id,
                "rule_groups",
                group_id,
            ],
            Some(body),
            cancellation,
        )
        .await
    }

    /// Read a preview job without polling.
    pub async fn preview_status(
        &self,
        preview_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("preview_id", preview_id)?;
        self.get(
            &["api", "v1", "policies", "preview", preview_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Read a deploy job without polling.
    pub async fn deploy_status(
        &self,
        deploy_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        validate_atom("deploy_id", deploy_id)?;
        self.get(
            &["api", "v1", "policies", "deploy", deploy_id],
            &[],
            cancellation,
        )
        .await
    }

    /// Fetch one per-device preview result in XML format.
    pub async fn preview_device_result(
        &self,
        preview_id: &str,
        device_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("preview_id", preview_id)?;
        validate_atom("device_id", device_id)?;
        self.get(
            &[
                "api", "v1", "policies", "preview", preview_id, "devices", device_id,
            ],
            &[("format", "XML")],
            cancellation,
        )
        .await
    }

    /// Fetch one per-device deploy result in CLI format.
    pub async fn deploy_device_result(
        &self,
        deploy_id: &str,
        device_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("deploy_id", deploy_id)?;
        validate_atom("device_id", device_id)?;
        self.get(
            &[
                "api", "v1", "policies", "deploy", deploy_id, "devices", device_id,
            ],
            &[("format", "CLI")],
            cancellation,
        )
        .await
    }

    /// Submit, resolve, and bind a batch policy preview.
    pub async fn prepare_policy_deploy(
        &self,
        policies: Vec<PolicyOperation>,
        cancellation: &CancellationToken,
    ) -> Result<SdcPreparedChange, SdcError> {
        validate_policy_operations(&policies)?;
        let preview_request = PreviewRequest { policies };
        let response: PreviewResponse = self
            .post(
                &["api", "v1", "policies", "preview"],
                &preview_request,
                cancellation,
            )
            .await?;
        validate_atom("preview_id", &response.preview_id)?;
        let status = self
            .poll_job(JobKind::Preview, &response.preview_id, cancellation)
            .await?;
        if !status.status.succeeded() {
            return Err(SdcError::JobFailed {
                status: status.status,
            });
        }

        let mut device_results = Vec::with_capacity(status.device_deployment_status.len());
        for device in &status.device_deployment_status {
            device_results.push(
                self.preview_device_result(&response.preview_id, &device.device_id, cancellation)
                    .await?,
            );
        }

        let targets = prepared_targets(&preview_request)?;
        let deploy_request = DeployRequest::from(&preview_request);
        let preview = serde_json::json!({
            "preview_request": preview_request,
            "status": status,
            "device_results": device_results,
        });
        SdcPreparedChange::new(
            targets,
            serde_json::to_value(deploy_request).map_err(|_| SdcError::Serialization)?,
            preview,
            response.preview_id,
        )
        .map_err(|error| SdcError::PreparedChange(error.to_string()))
    }

    /// Submit an exact prepared deploy request and resolve its documented job.
    pub async fn deploy_prepared(
        &self,
        request: &DeployRequest,
        cancellation: &CancellationToken,
    ) -> Result<(String, JobStatus), SdcError> {
        let response: DeployResponse = self
            .post(&["api", "v1", "policies", "deploy"], request, cancellation)
            .await?;
        validate_atom("deploy_id", &response.deploy_id)?;
        let status = self
            .poll_job(JobKind::Deploy, &response.deploy_id, cancellation)
            .await?;
        Ok((response.deploy_id, status))
    }

    async fn poll_job(
        &self,
        kind: JobKind,
        job_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<JobStatus, SdcError> {
        let deadline = Instant::now() + self.poll.deadline;
        let mut interval = self.poll.initial;
        loop {
            let probe = async {
                match kind {
                    JobKind::Preview => self.preview_status(job_id, cancellation).await,
                    JobKind::Deploy => self.deploy_status(job_id, cancellation).await,
                    JobKind::InstallLicense => {
                        self.install_license_status(job_id, cancellation).await
                    }
                    JobKind::InstallCaCertificate => {
                        self.install_ca_certificate_status(job_id, cancellation)
                            .await
                    }
                    JobKind::InstallLocalCertificate => {
                        self.install_local_certificate_status(job_id, cancellation)
                            .await
                    }
                    JobKind::DeleteCertificate => {
                        self.delete_certificate_status(job_id, cancellation).await
                    }
                }
            };
            let status = tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                result = probe => result?,
            };
            if status.status.is_terminal() {
                return Ok(status);
            }
            tokio::select! {
                () = cancellation.cancelled() => return Err(SdcError::Cancelled),
                () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
                () = time::sleep_until(deadline) => return Err(SdcError::JobDeadline),
                () = time::sleep(interval) => {}
            }
            interval = interval.saturating_mul(2).min(self.poll.maximum);
        }
    }

    async fn list(
        &self,
        segments: &[&str],
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_projected(segments, page, &[], cancellation).await
    }

    /// `list`, with the API's server-side `fields` projection.
    ///
    /// `size` bounds how many objects come back, not how large each one is. A
    /// collection whose members embed arrays -- device groups embed their
    /// membership -- can therefore exceed `max_response_bytes` even at
    /// `size=1`, which refuses the read rather than truncating it. `fields`
    /// is the API's own remedy (see docs/sdc-api/README.md, "Pagination,
    /// filtering, and result shaping").
    async fn list_projected(
        &self,
        segments: &[&str],
        page: ListRequest,
        fields: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let page = ListRequest::new(page.from, page.size, self.max_page_size)?;
        let mut query = vec![
            ("from", page.from.to_string()),
            ("size", page.size.to_string()),
        ];
        // The spec declares `fields` as `style: form, explode: true` over an
        // array, and its own example is `fields=uuid && fields=name`. One
        // comma-joined value is a different request, and would likely be read
        // as a single unknown field name.
        for field in fields {
            validate_atom("fields", field)?;
            query.push(("fields", field.clone()));
        }
        let borrowed = query
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect::<Vec<_>>();
        self.get(segments, &borrowed, cancellation).await
    }

    async fn get<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
        cancellation: &CancellationToken,
    ) -> Result<T, SdcError> {
        self.send::<(), T>(Method::GET, segments, query, None, cancellation)
            .await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        segments: &[&str],
        body: &B,
        cancellation: &CancellationToken,
    ) -> Result<T, SdcError> {
        self.send(Method::POST, segments, &[], Some(body), cancellation)
            .await
    }

    async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        cancellation: &CancellationToken,
    ) -> Result<T, SdcError> {
        let raw = self
            .send_raw(method, segments, query, body, cancellation)
            .await?;
        serde_json::from_slice(&raw).map_err(|_| SdcError::InvalidJson)
    }

    /// Send one request and return its raw successful response body.
    async fn send_raw<B: Serialize>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, SdcError> {
        let (status, body) = self
            .send_parts(method, segments, query, body, cancellation)
            .await?;
        let body = body?;
        if !status.is_success() {
            return Err(classify_api_error(status, &body));
        }
        Ok(body)
    }

    /// Send one request, reporting the response status separately from the body.
    ///
    /// The status is resolved first so a caller can tell a request SDC refused
    /// from one it accepted but whose body could not be read. Reads do not care
    /// about that distinction; writes do, because it decides whether a mutation
    /// landed.
    async fn send_parts<B: Serialize>(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&B>,
        cancellation: &CancellationToken,
    ) -> Result<(StatusCode, Result<Vec<u8>, SdcError>), SdcError> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| SdcError::UrlConstruction)?;
            path.clear();
            for segment in segments {
                if segment.is_empty() || matches!(*segment, "." | "..") {
                    return Err(SdcError::UrlConstruction);
                }
                path.push(segment);
            }
        }
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }

        let mut auth = HeaderValue::from_str(&self.credential.0)
            .map_err(|_| SdcError::InvalidCredentialHeader)?;
        auth.set_sensitive(true);
        let mut request = self
            .http
            .request(method, url)
            .header(self.auth_scheme.header_name(), auth)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }

        let operation = async {
            let _permit = self
                .concurrency
                .acquire()
                .await
                .map_err(|_| SdcError::Cancelled)?;
            let response = request
                .send()
                .await
                .map_err(|error| classify_reqwest(&error))?;
            // Read the status before any body handling. A write needs to know
            // whether SDC accepted the request even when the body is then
            // unreadable, because that decides whether the mutation landed.
            let status = response.status();
            let oversized = response
                .content_length()
                .is_some_and(|length| length > self.max_response_bytes as u64);
            let body = async {
                if oversized {
                    return Err(SdcError::ResponseTooLarge {
                        limit: self.max_response_bytes,
                    });
                }
                let mut body = Vec::new();
                let mut stream = response.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|error| classify_reqwest(&error))?;
                    if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                        return Err(SdcError::ResponseTooLarge {
                            limit: self.max_response_bytes,
                        });
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            }
            .await;
            Ok::<_, SdcError>((status, body))
        };

        tokio::select! {
            () = cancellation.cancelled() => Err(SdcError::Cancelled),
            () = self.shutdown.cancelled() => Err(SdcError::Cancelled),
            result = time::timeout(self.request_timeout, operation) => {
                result.map_err(|_| SdcError::Timeout)?
            }
        }
    }

    /// Send one mutating request whose successful response may carry no body.
    ///
    /// An empty or whitespace-only body resolves to `Value::Null` rather than
    /// an `InvalidJson` failure, because SDC answers some deletes that way.
    async fn send_write(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<&Value>,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let (status, raw) = self
            .send_parts(method, segments, &[], body, cancellation)
            .await?;
        let raw = match raw {
            Ok(bytes) => bytes,
            // SDC accepted the request, so the mutation may have landed even
            // though its response could not be read. Reporting a plain failure
            // here would invite a retry that duplicates a create.
            Err(_) if status.is_success() => return Err(SdcError::MutationOutcomeUnknown),
            Err(error) => return Err(error),
        };
        if !status.is_success() {
            return Err(classify_api_error(status, &raw));
        }
        if raw.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&raw).map_err(|_| SdcError::MutationOutcomeUnknown)
    }
}

#[derive(Debug, Clone, Copy)]
enum JobKind {
    Preview,
    Deploy,
    InstallLicense,
    InstallCaCertificate,
    InstallLocalCertificate,
    DeleteCertificate,
}

fn prepared_targets(request: &PreviewRequest) -> Result<Vec<SdcPreparedTarget>, SdcError> {
    let mut targets = Vec::new();
    for operation in &request.policies {
        for target in operation
            .deploy_targets
            .iter()
            .chain(&operation.undeploy_targets)
        {
            let kind = match target.target_type {
                crate::TargetType::Device => "device",
                crate::TargetType::DeviceGroup => "device_group",
            };
            targets.push(
                SdcPreparedTarget::new(kind, &target.target_id)
                    .map_err(|error| SdcError::PreparedChange(error.to_string()))?,
            );
        }
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn validate_policy_operations(policies: &[PolicyOperation]) -> Result<(), SdcError> {
    if policies.is_empty() || policies.len() > 256 {
        return Err(SdcError::InvalidInput(
            "policies must contain 1-256 entries",
        ));
    }
    for policy in policies {
        validate_atom("policy_id", &policy.policy_id)?;
        if policy.deploy_targets.is_empty() && policy.undeploy_targets.is_empty() {
            return Err(SdcError::InvalidInput(
                "each policy needs at least one deploy or undeploy target",
            ));
        }
    }
    Ok(())
}

/// Hard cap on one object-write request body.
const MAX_WRITE_BODY_BYTES: usize = 1024 * 1024;

/// Reject write bodies that are not a bounded, non-empty JSON object.
///
/// SDC object definitions are small; a scalar, an array, or a megabyte-scale
/// body indicates a caller error rather than a legitimate write.
fn validate_object_body(body: &Value) -> Result<(), SdcError> {
    let Value::Object(fields) = body else {
        return Err(SdcError::InvalidInput(
            "object write body must be a JSON object",
        ));
    };
    if fields.is_empty() {
        return Err(SdcError::InvalidInput(
            "object write body must not be empty",
        ));
    }
    if serde_json::to_vec(body)
        .map_err(|_| SdcError::Serialization)?
        .len()
        > MAX_WRITE_BODY_BYTES
    {
        return Err(SdcError::InvalidInput(
            "object write body exceeds the 1048576-byte limit",
        ));
    }
    Ok(())
}

fn validate_atom(field: &'static str, value: &str) -> Result<(), SdcError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(SdcError::InvalidIdentifier { field });
    }
    Ok(())
}

fn classify_reqwest(error: &reqwest::Error) -> SdcError {
    if error.is_timeout() {
        SdcError::Timeout
    } else if error.is_body() || error.is_decode() {
        SdcError::BodyTransfer
    } else if error.is_builder() {
        SdcError::UrlConstruction
    } else {
        SdcError::Transport
    }
}

fn classify_api_error(status: StatusCode, body: &[u8]) -> SdcError {
    if status == StatusCode::TOO_MANY_REQUESTS {
        return SdcError::ResourceExhausted;
    }
    let value: Option<Value> = serde_json::from_slice(body).ok();
    let code = value
        .as_ref()
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str)
        .map(bound_text)
        .unwrap_or_else(|| format!("http_{}", status.as_u16()));
    let message = value
        .as_ref()
        .and_then(|value| value.get("message").or_else(|| value.get("error")))
        .and_then(Value::as_str)
        .map(bound_text)
        .unwrap_or_else(|| "SDC API request failed".to_owned());
    SdcError::Api {
        status: status.as_u16(),
        code,
        message,
    }
}

fn bound_text(value: &str) -> String {
    mecmcp_server::bounded_text(value, 512).text
}

/// Stable, credential-free SDC client failure.
#[derive(Debug, thiserror::Error)]
pub enum SdcError {
    /// Configuration validation failed.
    #[error("SDC configuration failed: {0}")]
    Config(String),
    /// Credential was empty or excessive.
    #[error("SDC credential must contain 1-16384 bytes")]
    Credential,
    /// HTTPS client construction failed.
    #[error("SDC HTTPS client construction failed")]
    ClientConstruction,
    /// Request URL construction failed.
    #[error("failed to construct an SDC request URL")]
    UrlConstruction,
    /// Credential could not be represented as a header.
    #[error("SDC credential is not a valid HTTP header value")]
    InvalidCredentialHeader,
    /// Request transmission failed.
    #[error("SDC request transmission failed")]
    Transport,
    /// Response body transfer failed.
    #[error("SDC response body transfer failed")]
    BodyTransfer,
    /// Whole-request deadline elapsed.
    #[error("SDC request timed out")]
    Timeout,
    /// Response exceeded the configured cap.
    #[error("SDC response exceeds the {limit}-byte limit")]
    ResponseTooLarge {
        /// Configured maximum.
        limit: usize,
    },
    /// Successful response was not valid JSON.
    #[error("SDC response is not valid JSON")]
    InvalidJson,
    /// Invalid bounded list request.
    #[error(transparent)]
    List(#[from] ListRequestError),
    /// Credential tenant scope differed from operator configuration.
    #[error("credential tenant scope does not match expected_tenant_id")]
    TenantMismatch,
    /// SDC rejected the request.
    #[error("SDC API error {status} ({code}): {message}")]
    Api {
        /// HTTP status.
        status: u16,
        /// Bounded machine-readable code.
        code: String,
        /// Bounded SDC message.
        message: String,
    },
    /// SDC uses 429 for rate limiting and oversized service responses.
    #[error(
        "SDC resource exhausted: request was rate limited or the service response was too large; retry only after operator review"
    )]
    ResourceExhausted,
    /// A caller-controlled identifier was unsafe.
    #[error("{field} must be 1-256 non-whitespace bytes")]
    InvalidIdentifier {
        /// Rejected field.
        field: &'static str,
    },
    /// A structured input violated an SDC contract.
    #[error("{0}")]
    InvalidInput(&'static str),
    /// A prepared-change envelope could not be built or validated.
    #[error("invalid prepared change: {0}")]
    PreparedChange(String),
    /// JSON construction failed without exposing content.
    #[error("failed to serialize SDC request")]
    Serialization,
    /// Job polling or request was cancelled.
    #[error("SDC operation was cancelled")]
    Cancelled,
    /// Job polling reached its configured deadline.
    #[error("SDC job outcome is indeterminate because the polling deadline elapsed")]
    JobDeadline,
    /// SDC returned a documented terminal failure.
    #[error("SDC job ended with {status:?}")]
    JobFailed {
        /// Documented terminal state.
        status: DeploymentStatus,
    },
    /// Shared change-control operation failed.
    #[error("SDC change control failed: {0}")]
    ChangeControl(String),
    /// SDC has no candidate rollback primitive for this transaction.
    #[error("SDC policy deployment rollback is unsupported")]
    RollbackUnsupported,

    /// SDC accepted a mutation but its response could not be read.
    #[error(
        "SDC accepted the write but its response could not be read; the change may have been applied"
    )]
    MutationOutcomeUnknown,

    /// A change-controlled target moved between planning and writing.
    #[error("object changed since it was prepared; re-prepare to see the current state")]
    TargetDrifted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::Query,
        http::{HeaderMap, StatusCode},
        routing::{delete, get, post, put},
    };
    use std::collections::HashMap;

    async fn serve(app: Router) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test application");
        });
        (
            Url::parse(&format!("http://{address}/")).expect("test URL"),
            task,
        )
    }

    fn client(base_url: Url, max_response_bytes: usize) -> SdcClient {
        let _ = rustls::crypto::ring::default_provider().install_default();
        SdcClient::from_test_parts(base_url, "test-secret".to_owned(), max_response_bytes, 100)
    }

    #[tokio::test]
    async fn list_devices_sends_exact_auth_path_and_nonzero_page() {
        let app = Router::new().route(
            "/api/v1/devices",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("10"));
                    assert_eq!(query.get("size").map(String::as_str), Some("20"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_devices(
                ListRequest::new(10, 20, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn path_parameters_remain_one_encoded_segment() {
        // A hostile identifier must be percent-encoded into exactly one path
        // segment. Route it explicitly rather than with a fallback: a fallback
        // answers every path, so it would pass just as happily if the value
        // were split across segments or leaked into the query string.
        let app = Router::new()
            .route(
                "/api/v1/devices/{device_uuid}",
                get(
                    |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                     Query(query): Query<HashMap<String, String>>| async move {
                        Json(serde_json::json!({
                            "device_uuid": device_uuid,
                            "query_keys": query.into_keys().collect::<Vec<_>>(),
                        }))
                    },
                ),
            )
            .fallback(|uri: axum::http::Uri| async move {
                // Reached only if the identifier escaped its single segment.
                Json(serde_json::json!({"escaped_to": uri.to_string()}))
            });
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .get_device("a/b?admin=true#frag", &CancellationToken::new())
            .await
            .expect("encoded path succeeds");
        assert_eq!(
            result["device_uuid"], "a/b?admin=true#frag",
            "identifier did not survive as one encoded segment: {result}"
        );
        assert_eq!(
            result["query_keys"],
            serde_json::json!([]),
            "identifier leaked into the query string: {result}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn status_429_is_never_hidden_as_a_retryable_transport_error() {
        let app = Router::new().route(
            "/api/v1/devices",
            get(|| async {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({"message": "too many"})),
                )
            }),
        );
        let (base_url, server) = serve(app).await;
        let error = client(base_url, 4096)
            .list_devices(
                ListRequest::new(0, 20, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("429 must fail");
        assert!(matches!(error, SdcError::ResourceExhausted));
        server.abort();
    }

    #[tokio::test]
    async fn cancelling_the_request_token_aborts_an_in_flight_call() {
        // The MCP handler feeds each tool the per-request `RequestContext::ct`,
        // so a client `notifications/cancelled` must abandon the SDC call
        // instead of running to the whole-request timeout.
        let app = Router::new().route(
            "/api/v1/devices",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Json(serde_json::json!({"items": []}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });

        let started = std::time::Instant::now();
        let error = client(base_url, 4096)
            .list_devices(
                ListRequest::new(0, 20, 100).expect("test page"),
                &cancellation,
            )
            .await
            .expect_err("a cancelled request must fail");
        assert!(matches!(error, SdcError::Cancelled));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancellation must abandon the call, not wait for the 2s request timeout"
        );
        server.abort();
    }

    #[tokio::test]
    async fn process_shutdown_aborts_work_the_request_token_would_not() {
        // systemd stops the unit with SIGTERM while a request token is still
        // live. Without this the listener drain would block for the remainder
        // of poll_deadline_ms and be SIGKILLed at TimeoutStopSec.
        let app = Router::new().route(
            "/api/v1/devices",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Json(serde_json::json!({"items": []}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let shutdown = CancellationToken::new();
        let trigger = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });

        // The per-request token stays uncancelled throughout.
        let request_token = CancellationToken::new();
        let started = std::time::Instant::now();
        let error = client(base_url, 4096)
            .with_shutdown(shutdown)
            .list_devices(
                ListRequest::new(0, 20, 100).expect("test page"),
                &request_token,
            )
            .await
            .expect_err("shutdown must abort the call");
        assert!(matches!(error, SdcError::Cancelled));
        assert!(!request_token.is_cancelled());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown must abandon the call, not wait for the 2s request timeout"
        );
        server.abort();
    }

    #[tokio::test]
    async fn response_limit_is_enforced_while_streaming() {
        let app = Router::new().route(
            "/api/v1/devices",
            get(|| async { Json(serde_json::json!({"items": ["0123456789"]})) }),
        );
        let (base_url, server) = serve(app).await;
        let error = client(base_url, 8)
            .list_devices(
                ListRequest::new(0, 1, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("body cap must fail");
        assert!(matches!(error, SdcError::ResponseTooLarge { limit: 8 }));
        server.abort();
    }

    #[tokio::test]
    async fn create_resource_posts_the_body_to_the_exact_collection_path() {
        let app = Router::new().route(
            "/api/v1/addresses",
            post(|headers: HeaderMap, Json(body): Json<Value>| async move {
                assert_eq!(
                    headers
                        .get("x-api-key")
                        .and_then(|value| value.to_str().ok()),
                    Some("test-secret")
                );
                assert_eq!(body.get("name").and_then(Value::as_str), Some("lab-net"));
                Json(serde_json::json!({"uuid": "created", "name": "lab-net"}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let created = client(base_url, 65536)
            .create_resource(
                WritableResource::Addresses,
                &serde_json::json!({"name": "lab-net"}),
                &CancellationToken::new(),
            )
            .await
            .expect("create must succeed");
        assert_eq!(created.get("uuid").and_then(Value::as_str), Some("created"));
        server.abort();
    }

    #[tokio::test]
    async fn update_resource_puts_the_body_to_the_exact_item_path() {
        let app = Router::new().route(
            "/api/v1/services/svc-1",
            put(|Json(body): Json<Value>| async move {
                assert_eq!(body.get("name").and_then(Value::as_str), Some("telnet-alt"));
                Json(serde_json::json!({"uuid": "svc-1", "name": "telnet-alt"}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let updated = client(base_url, 65536)
            .update_resource(
                WritableResource::Services,
                "svc-1",
                &serde_json::json!({"name": "telnet-alt"}),
                &CancellationToken::new(),
            )
            .await
            .expect("update must succeed");
        assert_eq!(updated.get("uuid").and_then(Value::as_str), Some("svc-1"));
        server.abort();
    }

    #[tokio::test]
    async fn delete_resource_tolerates_an_empty_success_body() {
        let app = Router::new().route(
            "/api/v1/schedulers/sch-1",
            delete(|| async { StatusCode::NO_CONTENT }),
        );
        let (base_url, server) = serve(app).await;
        let deleted = client(base_url, 65536)
            .delete_resource(
                WritableResource::Schedulers,
                "sch-1",
                &CancellationToken::new(),
            )
            .await
            .expect("an empty delete response must not be an error");
        assert_eq!(deleted, Value::Null);
        server.abort();
    }

    #[tokio::test]
    async fn object_writes_reject_identifiers_that_could_escape_the_collection() {
        let sdc = client(
            Url::parse("https://example.invalid/").expect("test URL"),
            1024,
        );
        // `a/b` is deliberately absent: a slash is percent-encoded into a
        // single path segment rather than refused, which
        // `path_parameters_remain_one_encoded_segment` already pins down.
        for identifier in ["", ".", "..", "with space", "tab\there", "nul\0byte"] {
            let error = sdc
                .update_resource(
                    WritableResource::Addresses,
                    identifier,
                    &serde_json::json!({"name": "x"}),
                    &CancellationToken::new(),
                )
                .await
                .expect_err("invalid identifier must be refused before transport");
            // Two independent guards refuse these: `validate_atom` rejects
            // empty, whitespace, and control bytes, and the path builder
            // separately refuses `.` and `..`. Either is a safe refusal, and
            // neither reaches the network.
            assert!(
                matches!(
                    error,
                    SdcError::InvalidIdentifier { field: "uuid" } | SdcError::UrlConstruction
                ),
                "identifier {identifier:?} produced {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn object_writes_reject_bodies_that_are_not_a_populated_object() {
        let sdc = client(
            Url::parse("https://example.invalid/").expect("test URL"),
            1024,
        );
        for body in [
            serde_json::json!([]),
            serde_json::json!("scalar"),
            serde_json::json!(7),
            serde_json::json!({}),
        ] {
            let error = sdc
                .create_resource(
                    WritableResource::Addresses,
                    &body,
                    &CancellationToken::new(),
                )
                .await
                .expect_err("invalid body must be refused before transport");
            assert!(
                matches!(error, SdcError::InvalidInput(_)),
                "body {body} produced {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn list_ca_certificates_sends_exact_auth_path_and_page() {
        let app = Router::new().route(
            "/api/v1/devices/ca_certificates",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_ca_certificates(
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_device_groups_sends_exact_auth_path_and_page() {
        let app = Router::new().route(
            "/api/v1/device_groups",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    // An empty tenant returns a bare `{}` — see docs/sdc-api §3.
                    // Observed live on 2026-08-12 against this endpoint.
                    Json(serde_json::json!({}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_device_groups(
                ListRequest::new(0, 10, 100).expect("test page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result, serde_json::json!({}));
        server.abort();
    }

    #[tokio::test]
    async fn get_device_group_returns_member_devices() {
        let app = Router::new().route(
            "/api/v1/device_groups/{group_uuid}",
            get(|| async {
                Json(serde_json::json!({
                    "uuid": "group-1",
                    "name": "branches",
                    "devices": [{"uuid": "device-1"}, {"uuid": "device-2"}],
                }))
            }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let group = sdc
            .get_device_group("group-1", &CancellationToken::new())
            .await
            .expect("get succeeds");
        assert_eq!(
            group["devices"].as_array().map(Vec::len),
            Some(2),
            "membership is the whole point of this read: it is how an approver \
             sees the blast radius of a deploy aimed at the group"
        );

        server.abort();
    }

    #[tokio::test]
    async fn a_device_group_list_can_project_fields_and_omits_the_param_otherwise() {
        let app = Router::new().route(
            "/api/v1/device_groups",
            get(|uri: axum::http::Uri| async move {
                // Collect every `fields` pair: the spec explodes the array, so
                // a single comma-joined value would be the wrong request.
                let fields: Vec<String> = uri
                    .query()
                    .unwrap_or_default()
                    .split('&')
                    .filter_map(|pair| pair.strip_prefix("fields="))
                    .map(str::to_owned)
                    .collect();
                Json(serde_json::json!({"fields": fields}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let projected = sdc
            .list_device_groups(
                ListRequest::new(0, 10, 100).expect("test page"),
                &["uuid".to_owned(), "name".to_owned()],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(
            projected["fields"],
            serde_json::json!(["uuid", "name"]),
            "each field must be its own query item per the spec's exploded array"
        );

        // Absent by default: a projection invented here would silently drop
        // fields, and no live group has been observed to derive one from.
        let unprojected = sdc
            .list_device_groups(
                ListRequest::new(0, 10, 100).expect("test page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(unprojected["fields"], serde_json::json!([]));
        server.abort();
    }

    /// The generic reader projects with an exploded `fields` array, and omits
    /// the parameter entirely when no projection is asked for.
    ///
    /// The spec declares `fields` as `style: form, explode: true`, so
    /// `fields=uuid&fields=name` is the request and one comma-joined value
    /// would read as a single unknown field name. Omitting it when empty
    /// matters just as much: no default projection is invented for any
    /// family, because field names belong to the API and guessing them
    /// silently drops data.
    #[tokio::test]
    async fn a_resource_list_can_project_fields_and_omits_the_param_otherwise() {
        let app = Router::new().route(
            "/api/v1/ips_profiles",
            get(|uri: axum::http::Uri| async move {
                // Collect every `fields` pair: the spec explodes the array, so
                // a single comma-joined value would be the wrong request.
                let fields: Vec<String> = uri
                    .query()
                    .unwrap_or_default()
                    .split('&')
                    .filter_map(|pair| pair.strip_prefix("fields="))
                    .map(str::to_owned)
                    .collect();
                Json(serde_json::json!({"fields": fields}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let projected = sdc
            .list_resource(
                ResourceKind::IpsProfiles,
                ListRequest::new(0, 10, 200).expect("page"),
                &["uuid".to_owned(), "name".to_owned()],
                &CancellationToken::new(),
            )
            .await
            .expect("projected list succeeds");
        assert_eq!(
            projected["fields"],
            serde_json::json!(["uuid", "name"]),
            "each field must be its own query item per the spec's exploded array"
        );

        // Absent by default: a projection invented here would silently drop
        // fields, and no live resource has been observed to derive one from.
        let unprojected = sdc
            .list_resource(
                ResourceKind::IpsProfiles,
                ListRequest::new(0, 10, 200).expect("page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("unprojected list succeeds");
        assert_eq!(unprojected["fields"], serde_json::json!([]));
        server.abort();
    }

    /// A new family's list reaches its own collection path.
    ///
    /// The catalog's self-consistency tests prove the table agrees with itself.
    /// This proves the table is what the client actually requests.
    #[tokio::test]
    async fn a_new_family_lists_from_its_own_collection() {
        let app = Router::new().route(
            "/api/v1/rule_options",
            get(|| async { Json(serde_json::json!({"items": []})) }),
        );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        let listed = sdc
            .list_resource(
                ResourceKind::RuleOptions,
                ListRequest::new(0, 10, 200).expect("page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");

        assert_eq!(listed["items"], serde_json::json!([]));
        server.abort();
    }

    #[tokio::test]
    async fn a_device_group_uuid_cannot_escape_its_collection() {
        // `validate_atom` permits `/` and `.`, so the guarantee lives in the
        // URL builder: it refuses a literal `.`/`..` segment, and `push`
        // percent-encodes everything else into exactly one segment. Asserted
        // against the path the server actually receives rather than inferred.
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder
                    .lock()
                    .expect("record path")
                    .push(uri.path().to_owned());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        sdc.get_device_group("../devices", &CancellationToken::new())
            .await
            .expect("the request is built, not refused");
        let path = seen.lock().expect("read path")[0].clone();
        assert!(
            path.starts_with("/api/v1/device_groups/"),
            "a traversal attempt must stay inside the collection; got {path}"
        );
        assert!(
            !path.contains("/devices"),
            "the separator must be encoded rather than opening a new segment; got {path}"
        );

        // A literal traversal segment is refused outright.
        assert!(
            sdc.get_device_group("..", &CancellationToken::new())
                .await
                .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn certificate_reads_stay_unprojected_at_the_client_layer() {
        // The allowlist projection belongs at the MCP tool boundary, not here.
        // prepare_license_write and the apply-time drift check both read
        // through this method and digest the result, so projecting it would
        // erase an unknown field from both sides of the comparison and let a
        // drifted write apply as unchanged.
        let app = Router::new().route(
            "/api/v1/devices/ca_certificates",
            get(|| async {
                Json(serde_json::json!({
                    "items": [{"uuid": "u", "field_added_upstream": "visible"}],
                    "count": 1,
                }))
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_ca_certificates(
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");

        assert_eq!(
            result["items"][0]["field_added_upstream"], "visible",
            "the client must return upstream fields verbatim so change control \
             can detect drift in them"
        );
        server.abort();
    }

    #[tokio::test]
    async fn list_local_certificates_sends_exact_auth_path_and_page() {
        let app = Router::new().route(
            "/api/v1/devices/local_certificates",
            get(
                |headers: HeaderMap, Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(
                        headers
                            .get("x-api-key")
                            .and_then(|value| value.to_str().ok()),
                        Some("test-secret")
                    );
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_local_certificates(
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_device_ca_certificates_sends_device_uuid_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/ca_certificates",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-123");
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("5"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_device_ca_certificates(
                "dev-123",
                ListRequest::new(0, 5, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_device_local_certificates_sends_device_uuid_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/local_certificates",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-456");
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("5"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_device_local_certificates(
                "dev-456",
                ListRequest::new(0, 5, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn list_config_versions_sends_device_uuid_in_path_without_pagination() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/config/versions",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-789");
                    // This endpoint has no pagination parameters; adding them later
                    // would be a silent contract change.
                    assert!(
                        query.is_empty(),
                        "config versions endpoint must have no query parameters, found: {query:?}"
                    );
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_config_versions("dev-789", &CancellationToken::new())
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn a_device_uuid_in_config_versions_cannot_escape_its_collection() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let recorder = recorder.clone();
            async move {
                recorder
                    .lock()
                    .expect("record path")
                    .push(uri.path().to_owned());
                Json(serde_json::json!({}))
            }
        });
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);

        sdc.list_config_versions("../../api/v1/devices", &CancellationToken::new())
            .await
            .expect("the request is built, not refused");
        let path = seen.lock().expect("read path")[0].clone();
        assert!(
            !path.contains("/../"),
            "path traversal must be percent-encoded, not literal: {path}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn list_licenses_sends_device_uuid_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/licenses",
            get(
                |axum::extract::Path(device_uuid): axum::extract::Path<String>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(device_uuid, "dev-789");
                    assert_eq!(query.get("from").map(String::as_str), Some("0"));
                    assert_eq!(query.get("size").map(String::as_str), Some("10"));
                    Json(serde_json::json!({"items": [], "count": 0}))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_licenses(
                "dev-789",
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["count"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn get_license_sends_both_uuids_in_path() {
        let app = Router::new().route(
            "/api/v1/devices/{device_uuid}/licenses/{license_uuid}",
            get(
                |axum::extract::Path((device_uuid, license_uuid)): axum::extract::Path<(
                    String,
                    String,
                )>| async move {
                    assert_eq!(device_uuid, "dev-abc");
                    assert_eq!(license_uuid, "lic-xyz");
                    Json(serde_json::json!({
                        "uuid": "lic-xyz",
                        "name": "test-license",
                        "state": "valid"
                    }))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .get_license("dev-abc", "lic-xyz", &CancellationToken::new())
            .await
            .expect("get succeeds");
        assert_eq!(result["uuid"], "lic-xyz");
        assert_eq!(result["name"], "test-license");
        server.abort();
    }

    #[tokio::test]
    async fn license_and_certificate_methods_validate_identifiers() {
        let sdc = client(
            Url::parse("https://example.invalid/").expect("test URL"),
            1024,
        );
        // Empty device_uuid is refused
        let error = sdc
            .list_device_ca_certificates(
                "",
                ListRequest::new(0, 10, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect_err("empty device_uuid must be refused");
        assert!(matches!(
            error,
            SdcError::InvalidIdentifier {
                field: "device_uuid"
            }
        ));

        // Control character in license_uuid is refused
        let error = sdc
            .get_license("dev-1", "lic\n123", &CancellationToken::new())
            .await
            .expect_err("license_uuid with control char must be refused");
        assert!(matches!(
            error,
            SdcError::InvalidIdentifier {
                field: "license_uuid"
            }
        ));
    }

    #[tokio::test]
    async fn preview_device_result_requests_xml_format() {
        let app = Router::new().route(
            "/api/v1/policies/preview/{preview_id}/devices/{device_id}",
            get(
                |axum::extract::Path((preview_id, device_id)): axum::extract::Path<(
                    String,
                    String,
                )>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(preview_id, "preview-123");
                    assert_eq!(device_id, "device-456");
                    assert_eq!(
                        query.get("format").map(String::as_str),
                        Some("XML"),
                        "preview_device_result must request XML format, not CLI"
                    );
                    Json(serde_json::json!({
                        "config_diff": "<configuration></configuration>"
                    }))
                },
            ),
        );
        let (base_url, server) = serve(app).await;
        let _result = client(base_url, 4096)
            .preview_device_result("preview-123", "device-456", &CancellationToken::new())
            .await
            .expect("preview_device_result succeeds");
        server.abort();
    }
}
