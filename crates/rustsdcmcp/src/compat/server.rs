use mecmcp_audit::AuditScope;
use mecmcp_auth::{CallerCtx, Grant};
use rmcp::model::{CallToolResult, ContentBlock, Extensions, Tool};
use serde::Serialize;
use std::fmt::Display;

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/98 mecmcp_server::AuthorizationError
/// A handler-level scope denial safe to return to an MCP caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AuthorizationError {
    /// The caller's tool scope does not permit the requested tool.
    #[error("token '{token}' is not authorized for tool '{tool}'")]
    ToolNotInScope {
        /// Non-secret token name.
        token: String,
        /// Requested MCP tool.
        tool: String,
    },
    /// The caller's target scope does not permit the requested target.
    #[error("token '{token}' is not authorized for the requested target (tool '{tool}')")]
    TargetNotInScope {
        /// Non-secret token name.
        token: String,
        /// Requested MCP tool.
        tool: String,
        /// Caller-supplied target, retained for structured handling.
        target: String,
    },
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/99 mecmcp_server::ResultFormat
/// How successful serializable values are rendered into text content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResultFormat {
    /// Render every value as indented JSON.
    PrettyJson,
    /// Preserve a JSON string as raw text; render every other value as indented JSON.
    StringOrPrettyJson,
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/100 mecmcp_server::ResultLimits
/// Hard byte limits applied before a successful MCP result is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResultLimits {
    /// Maximum bytes in the final text content.
    pub(crate) max_text_bytes: usize,
    /// Maximum bytes in the serialized JSON representation.
    pub(crate) max_json_bytes: usize,
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/119 mecmcp_server::audit_scope
/// Construct an audit scope for an authenticated caller or the stdio path.
#[must_use]
pub(crate) fn audit_scope<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &'static str,
    action: &'static str,
    targets: Vec<String>,
) -> AuditScope {
    match caller {
        Some(caller) => AuditScope::from_caller(caller, tool, action, targets),
        None => AuditScope::stdio(tool, action, targets),
    }
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/120 mecmcp_server::authorize_tool
/// Require the caller's tool scope to permit `tool`.
pub(crate) fn authorize_tool<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    write_tools: &[&str],
) -> Result<(), AuthorizationError> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if caller.tools.allows_tool(tool, write_tools) {
        return Ok(());
    }
    Err(AuthorizationError::ToolNotInScope {
        token: caller.token_name.clone(),
        tool: tool.to_owned(),
    })
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/121 mecmcp_server::authorize_target
/// Require the caller's target scope to permit `target` without inventory lookup.
pub(crate) fn authorize_target<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    target: &str,
) -> Result<(), AuthorizationError> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if caller.devices.allows(target) {
        return Ok(());
    }
    Err(AuthorizationError::TargetNotInScope {
        token: caller.token_name.clone(),
        tool: tool.to_owned(),
        target: target.to_owned(),
    })
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/122 mecmcp_server::authorize_call
/// Check tool scope followed by an optional target scope.
pub(crate) fn authorize_call<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    target: Option<&str>,
    write_tools: &[&str],
) -> Result<(), AuthorizationError> {
    authorize_tool(caller, tool, write_tools)?;
    if let Some(target) = target {
        authorize_target(caller, tool, target)?;
    }
    Ok(())
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/123 mecmcp_server::caller_from_extensions
/// Recover the authenticated caller from nested HTTP request parts.
#[must_use]
pub(crate) fn caller_from_extensions<G: Grant>(extensions: &Extensions) -> Option<&CallerCtx<G>> {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<CallerCtx<G>>())
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/125 mecmcp_server::tool_error
/// Build an MCP tool error containing one safe text block.
#[must_use]
pub(crate) fn tool_error(error: impl Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(error.to_string())])
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/126 mecmcp_server::tool_result
/// Convert a domain result into a bounded MCP tool result.
#[must_use]
pub(crate) fn tool_result<T, E>(
    result: Result<T, E>,
    format: ResultFormat,
    limits: ResultLimits,
) -> CallToolResult
where
    T: Serialize,
    E: Display,
{
    let value = match result {
        Ok(value) => value,
        Err(error) => return tool_error(error),
    };
    let serialized = match serialize_value(&value, format) {
        Ok(serialized) => serialized,
        Err(error) => return tool_error(format!("failed to serialize tool result: {error}")),
    };
    if serialized.json_bytes > limits.max_json_bytes {
        return tool_error(format!(
            "serialized JSON exceeds the {}-byte limit",
            limits.max_json_bytes
        ));
    }
    if serialized.text.len() > limits.max_text_bytes {
        return tool_error(format!(
            "tool result text exceeds the {}-byte limit",
            limits.max_text_bytes
        ));
    }
    CallToolResult::success(vec![ContentBlock::text(serialized.text)])
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/102 mecmcp_server::SerializedValue
struct SerializedValue {
    text: String,
    json_bytes: usize,
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/127 mecmcp_server::serialize_value
fn serialize_value<T: Serialize>(
    value: &T,
    format: ResultFormat,
) -> Result<SerializedValue, serde_json::Error> {
    match format {
        ResultFormat::PrettyJson => {
            let text = serde_json::to_string_pretty(value)?;
            Ok(SerializedValue {
                json_bytes: text.len(),
                text,
            })
        }
        ResultFormat::StringOrPrettyJson => {
            let value = serde_json::to_value(value)?;
            match value {
                serde_json::Value::String(text) => {
                    let json_bytes = serde_json::to_string(&text)?.len();
                    Ok(SerializedValue { text, json_bytes })
                }
                value => {
                    let text = serde_json::to_string_pretty(&value)?;
                    Ok(SerializedValue {
                        json_bytes: text.len(),
                        text,
                    })
                }
            }
        }
    }
}

// mecmcp-compat: https://github.com/fastrevmd-lab/mecmcp/issues/128 mecmcp_server::filter_tools_for_scope
/// Filter tools down to the exact set the caller may invoke.
#[must_use]
pub(crate) fn filter_tools_for_scope<G: Grant>(
    tools: Vec<Tool>,
    caller: Option<&CallerCtx<G>>,
    write_tools: &[&str],
) -> Vec<Tool> {
    let Some(caller) = caller else {
        return tools;
    };
    tools
        .into_iter()
        .filter(|tool| caller.tools.allows_tool(tool.name.as_ref(), write_tools))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};

    fn caller_with(devices: ScopeSet, tools: ScopeSet) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: "reader".to_owned(),
            devices,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
        }
    }

    #[test]
    fn wildcard_scope_excludes_consumer_write_tools() {
        let caller = caller_with(ScopeSet::Wildcard, ScopeSet::Wildcard);
        assert!(
            authorize_call(
                Some(&caller),
                "get_sdc_tenant_scope",
                Some("production"),
                crate::WRITE_TOOLS,
            )
            .is_ok()
        );
        assert!(matches!(
            authorize_call(
                Some(&caller),
                "apply_sdc_change_set",
                Some("production"),
                crate::WRITE_TOOLS,
            ),
            Err(AuthorizationError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn oversized_success_is_an_mcp_error() {
        let result = tool_result::<_, std::convert::Infallible>(
            Ok("0123456789"),
            ResultFormat::StringOrPrettyJson,
            ResultLimits {
                max_text_bytes: 4,
                max_json_bytes: 32,
            },
        );
        assert_eq!(result.is_error, Some(true));
    }
}
