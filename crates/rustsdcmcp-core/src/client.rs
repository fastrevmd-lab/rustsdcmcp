//! Bounded SDC HTTPS client.
//!
//! The product-specific implementation here is intentionally isolated while
//! its reusable foundations are tracked in mecmcp issue #90.

use crate::{
    DeployRequest, DeploymentStatus, JobStatus, ListRequest, ListRequestError, PolicyOperation,
    PreviewRequest, ResourceKind, SdcConfig, SdcPreparedChange, SdcPreparedTarget, TenantScope,
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

    /// List one allowlisted generic resource family.
    pub async fn list_resource(
        &self,
        kind: ResourceKind,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list(kind.collection_segments(), page, cancellation)
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

    /// Fetch one per-device preview result in CLI format.
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
            &[("format", "CLI")],
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
        let page = ListRequest::new(page.from, page.size, self.max_page_size)?;
        let query = [
            ("from", page.from.to_string()),
            ("size", page.size.to_string()),
        ];
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
            if response
                .content_length()
                .is_some_and(|length| length > self.max_response_bytes as u64)
            {
                return Err(SdcError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                });
            }
            let status = response.status();
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
            Ok::<_, SdcError>((status, body))
        };

        let (status, body) = tokio::select! {
            () = cancellation.cancelled() => return Err(SdcError::Cancelled),
            () = self.shutdown.cancelled() => return Err(SdcError::Cancelled),
            result = time::timeout(self.request_timeout, operation) => {
                result.map_err(|_| SdcError::Timeout)??
            }
        };
        if !status.is_success() {
            return Err(classify_api_error(status, &body));
        }
        serde_json::from_slice(&body).map_err(|_| SdcError::InvalidJson)
    }
}

#[derive(Debug, Clone, Copy)]
enum JobKind {
    Preview,
    Deploy,
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
    crate::compat::bounded_text(value, 512).text
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::Query,
        http::{HeaderMap, StatusCode},
        routing::get,
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
}
