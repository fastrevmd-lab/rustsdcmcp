use crate::compat::preflight::ToolScopePreflight;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use mecmcp_auth::{CallerCtx, NoGrant};
use mecmcp_transport::{OptionalPreflight, preflight::run_preflight};
use serde_json::json;
use std::sync::Arc;

const MAX_AUTHORIZATION_HEADER_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
/// mecmcp-compat: type mecmcp_auth::BearerSyntax https://github.com/fastrevmd-lab/mecmcp/issues/96
pub(crate) enum BearerSyntax {
    Strict,
    Trimmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
/// mecmcp-compat: type mecmcp_auth::BearerHeaderError https://github.com/fastrevmd-lab/mecmcp/issues/97
pub(crate) enum BearerHeaderError {
    #[error("authorization header is too large")]
    TooLarge,
    #[error("authorization header contains invalid characters")]
    InvalidCharacters,
    #[error("authorization header must use the Bearer scheme")]
    WrongScheme,
    #[error("bearer credential is empty")]
    Empty,
    #[error("bearer credential contains whitespace")]
    EmbeddedWhitespace,
}

/// mecmcp-compat: type mecmcp_transport::Authenticate https://github.com/fastrevmd-lab/mecmcp/issues/103
type Authenticate = dyn Fn(&str) -> Option<CallerCtx<NoGrant>> + Send + Sync;

#[derive(Clone)]
/// mecmcp-compat: type mecmcp_transport::BearerAuthenticator https://github.com/fastrevmd-lab/mecmcp/issues/104
pub(crate) struct BearerAuthenticator {
    syntax: BearerSyntax,
    authenticate: Arc<Authenticate>,
}

impl BearerAuthenticator {
    /// mecmcp-compat: method BearerAuthenticator::new https://github.com/fastrevmd-lab/mecmcp/issues/129
    pub(crate) fn new(
        syntax: BearerSyntax,
        authenticate: impl Fn(&str) -> Option<CallerCtx<NoGrant>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            syntax,
            authenticate: Arc::new(authenticate),
        }
    }

    /// mecmcp-compat: method BearerAuthenticator::authenticate https://github.com/fastrevmd-lab/mecmcp/issues/130
    fn authenticate(&self, candidate: &str) -> Option<CallerCtx<NoGrant>> {
        (self.authenticate)(candidate)
    }
}

#[derive(Clone)]
/// mecmcp-compat: type mecmcp_transport::BearerResponseProfile https://github.com/fastrevmd-lab/mecmcp/issues/105
pub(crate) struct BearerResponseProfile {
    realm: String,
    style: BearerResponseStyle,
}

#[derive(Clone)]
#[allow(dead_code)]
/// mecmcp-compat: type mecmcp_transport::BearerResponseStyle https://github.com/fastrevmd-lab/mecmcp/issues/106
pub(crate) enum BearerResponseStyle {
    Detailed,
    Compact,
}

impl BearerResponseProfile {
    /// mecmcp-compat: method BearerResponseProfile::detailed https://github.com/fastrevmd-lab/mecmcp/issues/131
    pub(crate) fn detailed(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            style: BearerResponseStyle::Detailed,
        }
    }
}

#[derive(Clone)]
/// mecmcp-compat: type mecmcp_transport::BearerBoundary https://github.com/fastrevmd-lab/mecmcp/issues/107
pub(crate) struct BearerBoundary {
    authenticator: BearerAuthenticator,
    responses: BearerResponseProfile,
    body_limit: usize,
    preflight: OptionalPreflight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// mecmcp-compat: type mecmcp_transport::PresentationError https://github.com/fastrevmd-lab/mecmcp/issues/108
enum PresentationError {
    Missing,
    Malformed,
}

impl BearerBoundary {
    /// mecmcp-compat: method BearerBoundary::new https://github.com/fastrevmd-lab/mecmcp/issues/132
    pub(crate) fn new(
        authenticator: BearerAuthenticator,
        responses: BearerResponseProfile,
        body_limit: usize,
    ) -> Self {
        Self {
            authenticator,
            responses,
            body_limit,
            preflight: None,
        }
    }

    /// mecmcp-compat: method BearerBoundary::with_preflight https://github.com/fastrevmd-lab/mecmcp/issues/133
    pub(crate) fn with_preflight(mut self, preflight: ToolScopePreflight) -> Self {
        self.preflight = Some(Arc::new(preflight));
        self
    }
}

/// mecmcp-compat: function mecmcp_transport::apply_bearer_boundary https://github.com/fastrevmd-lab/mecmcp/issues/134
pub(crate) fn apply_bearer_boundary(router: Router, boundary: BearerBoundary) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        boundary,
        bearer_boundary,
    ))
}

/// mecmcp-compat: function mecmcp_transport::bearer_boundary https://github.com/fastrevmd-lab/mecmcp/issues/135
async fn bearer_boundary(
    State(boundary): State<BearerBoundary>,
    request: Request,
    next: Next,
) -> Response {
    let candidate = match bearer_candidate(&request, boundary.authenticator.syntax) {
        Ok(candidate) => candidate,
        Err(PresentationError::Missing | PresentationError::Malformed) => {
            return unauthorized(&boundary.responses);
        }
    };
    let Some(caller) = boundary.authenticator.authenticate(candidate) else {
        return invalid_token(&boundary.responses);
    };

    let (mut parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, boundary.body_limit).await {
        Ok(bytes) => bytes,
        Err(_) => return payload_too_large(),
    };
    if let Err(reason) = run_preflight(&boundary.preflight, &body_bytes, &caller) {
        return forbidden(&boundary.responses.realm, &reason);
    }

    parts.extensions.insert(caller);
    next.run(Request::from_parts(parts, Body::from(body_bytes)))
        .await
}

/// mecmcp-compat: function mecmcp_transport::bearer_candidate https://github.com/fastrevmd-lab/mecmcp/issues/136
fn bearer_candidate(request: &Request, syntax: BearerSyntax) -> Result<&str, PresentationError> {
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(PresentationError::Missing)?;
    if values.next().is_some() {
        return Err(PresentationError::Malformed);
    }
    let value = value.to_str().map_err(|_| PresentationError::Malformed)?;
    parse_bearer_header(value, syntax).map_err(|_| PresentationError::Malformed)
}

/// mecmcp-compat: function mecmcp_transport::unauthorized https://github.com/fastrevmd-lab/mecmcp/issues/137
fn unauthorized(profile: &BearerResponseProfile) -> Response {
    match profile.style {
        BearerResponseStyle::Detailed => response(
            StatusCode::UNAUTHORIZED,
            format!(r#"Bearer realm="{}""#, profile.realm),
            json!({"error": "invalid_request"}),
        ),
        BearerResponseStyle::Compact => invalid_token(profile),
    }
}

/// mecmcp-compat: function mecmcp_transport::invalid_token https://github.com/fastrevmd-lab/mecmcp/issues/138
fn invalid_token(profile: &BearerResponseProfile) -> Response {
    let challenge = format!(r#"Bearer realm="{}", error="invalid_token""#, profile.realm);
    response(
        StatusCode::UNAUTHORIZED,
        challenge,
        json!({"error": "invalid_token"}),
    )
}

/// mecmcp-compat: function mecmcp_transport::forbidden https://github.com/fastrevmd-lab/mecmcp/issues/139
fn forbidden(realm: &str, reason: &str) -> Response {
    response(
        StatusCode::FORBIDDEN,
        format!(r#"Bearer realm="{realm}", error="{reason}""#),
        json!({"error": reason}),
    )
}

/// mecmcp-compat: function mecmcp_transport::response https://github.com/fastrevmd-lab/mecmcp/issues/140
fn response(status: StatusCode, challenge: String, body: serde_json::Value) -> Response {
    (
        status,
        [(header::WWW_AUTHENTICATE, challenge)],
        axum::Json(body),
    )
        .into_response()
}

/// mecmcp-compat: function mecmcp_transport::payload_too_large https://github.com/fastrevmd-lab/mecmcp/issues/141
fn payload_too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        axum::Json(json!({"error": "request_too_large"})),
    )
        .into_response()
}

/// mecmcp-compat: function mecmcp_auth::parse_bearer_header https://github.com/fastrevmd-lab/mecmcp/issues/118
pub(crate) fn parse_bearer_header(
    value: &str,
    syntax: BearerSyntax,
) -> Result<&str, BearerHeaderError> {
    if value.len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return Err(BearerHeaderError::TooLarge);
    }
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (byte.is_ascii() && !byte.is_ascii_control()))
    {
        return Err(BearerHeaderError::InvalidCharacters);
    }
    let value = match syntax {
        BearerSyntax::Strict => value,
        BearerSyntax::Trimmed => {
            value.trim_matches(|character: char| character.is_ascii_whitespace())
        }
    };
    let Some(separator) = value.find(|character: char| character.is_ascii_whitespace()) else {
        return if value.eq_ignore_ascii_case("bearer") {
            Err(BearerHeaderError::Empty)
        } else {
            Err(BearerHeaderError::WrongScheme)
        };
    };
    let (scheme, remainder) = value.split_at(separator);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(BearerHeaderError::WrongScheme);
    }
    let credential = remainder.trim_matches(|character: char| character.is_ascii_whitespace());
    if credential.is_empty() {
        return Err(BearerHeaderError::Empty);
    }
    if credential
        .chars()
        .any(|character| character.is_ascii_whitespace())
    {
        return Err(BearerHeaderError::EmbeddedWhitespace);
    }
    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_bearer_parser_is_bounded_and_credential_free() {
        assert_eq!(
            parse_bearer_header("Bearer abc", BearerSyntax::Strict),
            Ok("abc"),
        );
        assert_eq!(
            parse_bearer_header(" Bearer abc", BearerSyntax::Strict),
            Err(BearerHeaderError::WrongScheme),
        );
        assert_eq!(
            parse_bearer_header("Bearer a b", BearerSyntax::Strict),
            Err(BearerHeaderError::EmbeddedWhitespace),
        );
        let oversized = format!("Bearer {}", "x".repeat(4096));
        assert_eq!(
            parse_bearer_header(&oversized, BearerSyntax::Strict),
            Err(BearerHeaderError::TooLarge),
        );
        assert!(
            !BearerHeaderError::EmbeddedWhitespace
                .to_string()
                .contains("a b")
        );
    }
}
