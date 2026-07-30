//! Temporary test-only MCP transport support.

use reqwest::{
    Method, Url,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use serde_json::{Value, json};
use std::{error::Error, fmt, time::Duration};

const INVALID_PAYLOAD: &str = "MCP response did not contain a valid JSON payload";
const RESPONSE_TOO_LARGE: &str = "MCP response exceeded the configured size limit";
const INVALID_CONFIGURATION: &str = "MCP verifier configuration is invalid";
const INVALID_CONTRACT: &str = "deployed MCP response did not satisfy the expected contract";
const CLIENT_FAILURE: &str = "MCP verifier HTTP client setup failed";
const REQUEST_FAILURE: &str = "MCP request failed";
const SESSION_REQUIRED: &str = "MCP response did not establish a session";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MCP_ACCEPT: &str = "application/json, text/event-stream";
const MCP_SESSION_ID: &str = "mcp-session-id";

#[derive(Debug)]
pub(crate) struct SafeTransportError(&'static str);

impl fmt::Display for SafeTransportError {
    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for SafeTransportError {}

impl SafeTransportError {
    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) fn invalid_configuration() -> Self {
        Self(INVALID_CONFIGURATION)
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) fn invalid_contract() -> Self {
        Self(INVALID_CONTRACT)
    }
}

pub(crate) struct BodyAccumulator {
    bytes: Vec<u8>,
    limit: usize,
}

impl BodyAccumulator {
    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), SafeTransportError> {
        if chunk.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(SafeTransportError(RESPONSE_TOO_LARGE));
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub(crate) struct McpHttpClient {
    http: reqwest::Client,
    url: Url,
    authorization: Option<HeaderValue>,
    session_id: Option<HeaderValue>,
    next_id: u64,
}

impl McpHttpClient {
    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) fn new(url: &str, bearer: Option<&str>) -> Result<Self, SafeTransportError> {
        if url.is_empty() {
            return Err(SafeTransportError(INVALID_CONFIGURATION));
        }
        let url = Url::parse(url).map_err(|_| SafeTransportError(INVALID_CONFIGURATION))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(SafeTransportError(INVALID_CONFIGURATION));
        }

        let authorization = bearer.map(build_bearer).transpose()?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| SafeTransportError(CLIENT_FAILURE))?;

        Ok(Self {
            http,
            url,
            authorization,
            session_id: None,
            next_id: 1,
        })
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) async fn initialize(
        &mut self,
        protocol_version: &str,
    ) -> Result<Value, SafeTransportError> {
        let id = self.take_id();
        let response = self
            .post(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": protocol_version,
                        "capabilities": {},
                        "clientInfo": {
                            "name": "rustsdcmcp-deployed-verifier",
                            "version": "1"
                        }
                    }
                }),
                Some(id),
            )
            .await?
            .ok_or(SafeTransportError(INVALID_PAYLOAD))?;
        if self.session_id.is_none() {
            return Err(SafeTransportError(SESSION_REQUIRED));
        }
        if response.get("result").and_then(Value::as_object).is_none()
            || response.get("error").is_some_and(|error| !error.is_null())
        {
            return Err(SafeTransportError(INVALID_CONTRACT));
        }
        Ok(response)
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) async fn notify_initialized(&mut self) -> Result<(), SafeTransportError> {
        self.post(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }),
            None,
        )
        .await?;
        Ok(())
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) async fn list_tools(&mut self) -> Result<Value, SafeTransportError> {
        let id = self.take_id();
        self.post(
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/list",
                "params": {}
            }),
            Some(id),
        )
        .await?
        .ok_or(SafeTransportError(INVALID_PAYLOAD))
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) async fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, SafeTransportError> {
        let id = self.take_id();
        self.post(
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments
                }
            }),
            Some(id),
        )
        .await?
        .ok_or(SafeTransportError(INVALID_PAYLOAD))
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    pub(crate) async fn close(&mut self) -> Result<(), SafeTransportError> {
        let Some(session_id) = self.session_id.take() else {
            return Ok(());
        };
        let mut request = self
            .http
            .request(Method::DELETE, self.url.clone())
            .header(ACCEPT, MCP_ACCEPT)
            .header(CONTENT_TYPE, "application/json")
            .header(MCP_SESSION_ID, session_id);
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        let response = request
            .send()
            .await
            .map_err(|_| SafeTransportError(REQUEST_FAILURE))?;
        if !response.status().is_success() {
            return Err(SafeTransportError(REQUEST_FAILURE));
        }
        read_response_body(response).await?;
        Ok(())
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
    async fn post(
        &mut self,
        payload: Value,
        expected_id: Option<u64>,
    ) -> Result<Option<Value>, SafeTransportError> {
        let mut request = self
            .http
            .request(Method::POST, self.url.clone())
            .header(ACCEPT, MCP_ACCEPT)
            .header(CONTENT_TYPE, "application/json")
            .json(&payload);
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        if let Some(session_id) = &self.session_id {
            request = request.header(MCP_SESSION_ID, session_id.clone());
        }

        let response = request
            .send()
            .await
            .map_err(|_| SafeTransportError(REQUEST_FAILURE))?;
        if !response.status().is_success() {
            return Err(SafeTransportError(REQUEST_FAILURE));
        }

        if let Some(value) = response.headers().get(MCP_SESSION_ID)
            && self.session_id.is_none()
        {
            let mut session_id = value.clone();
            session_id.set_sensitive(true);
            self.session_id = Some(session_id);
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = read_response_body(response).await?;

        if let Some(expected_id) = expected_id {
            parse_mcp_response(content_type.as_deref(), &body, expected_id).map(Some)
        } else {
            Ok(None)
        }
    }
}

// Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
fn build_bearer(bearer: &str) -> Result<HeaderValue, SafeTransportError> {
    if bearer.len() < 32
        || !bearer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(SafeTransportError(INVALID_CONFIGURATION));
    }
    let mut value = b"Bearer ".to_vec();
    value.extend_from_slice(bearer.as_bytes());
    let mut header =
        HeaderValue::from_bytes(&value).map_err(|_| SafeTransportError(INVALID_CONFIGURATION))?;
    header.set_sensitive(true);
    Ok(header)
}

// Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
async fn read_response_body(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, SafeTransportError> {
    let mut body = BodyAccumulator::new(MAX_RESPONSE_BYTES);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| SafeTransportError(REQUEST_FAILURE))?
    {
        body.push(&chunk)?;
    }
    Ok(body.into_bytes())
}

// Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
pub(crate) fn parse_mcp_response(
    content_type: Option<&str>,
    body: &[u8],
    expected_id: u64,
) -> Result<Value, SafeTransportError> {
    let media_type = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);

    match media_type {
        Some(value) if value.eq_ignore_ascii_case("application/json") => {
            let payload =
                serde_json::from_slice(body).map_err(|_| SafeTransportError(INVALID_PAYLOAD))?;
            if is_applicable_response(&payload, expected_id) {
                Ok(payload)
            } else {
                Err(SafeTransportError(INVALID_PAYLOAD))
            }
        }
        Some(value) if value.eq_ignore_ascii_case("text/event-stream") => {
            parse_sse_response(body, expected_id)
        }
        _ => Err(SafeTransportError(INVALID_PAYLOAD)),
    }
}

// Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
fn parse_sse_response(body: &[u8], expected_id: u64) -> Result<Value, SafeTransportError> {
    let text = std::str::from_utf8(body).map_err(|_| SafeTransportError(INVALID_PAYLOAD))?;
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut remaining = normalized.as_str();

    while let Some(record_end) = remaining.find("\n\n") {
        let record = &remaining[..record_end];
        remaining = &remaining[record_end + 2..];
        let data = record
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|value| value.strip_prefix(' ').unwrap_or(value))
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            continue;
        }
        if let Ok(payload) = serde_json::from_str(&data)
            && is_applicable_response(&payload, expected_id)
        {
            return Ok(payload);
        }
    }

    Err(SafeTransportError(INVALID_PAYLOAD))
}

// Temporary test transport pending https://github.com/fastrevmd-lab/mecmcp/issues/184
fn is_applicable_response(payload: &Value, expected_id: u64) -> bool {
    payload.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && payload.get("id").and_then(Value::as_u64) == Some(expected_id)
        && payload.get("method").is_none()
        && (payload.get("result").is_some() || payload.get("error").is_some())
}
