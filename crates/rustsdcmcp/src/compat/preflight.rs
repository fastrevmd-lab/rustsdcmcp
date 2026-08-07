use mecmcp_auth::ScopeSet;
use mecmcp_transport::{CallerScopes, ScopePreflight};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
/// mecmcp-compat: type mecmcp_transport::MalformedArgumentsPolicy https://github.com/fastrevmd-lab/mecmcp/issues/109
pub(crate) enum MalformedArgumentsPolicy {
    Deny,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// mecmcp-compat: type mecmcp_transport::MalformedTargetPolicy https://github.com/fastrevmd-lab/mecmcp/issues/110
pub(crate) enum MalformedTargetPolicy {
    Deny,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
/// mecmcp-compat: type mecmcp_transport::TargetValueShape https://github.com/fastrevmd-lab/mecmcp/issues/111
pub(crate) enum TargetValueShape {
    Scalar,
    NonEmptyArray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// mecmcp-compat: type mecmcp_transport::TargetField https://github.com/fastrevmd-lab/mecmcp/issues/112
pub(crate) struct TargetField {
    name: &'static str,
    shape: TargetValueShape,
    malformed: MalformedTargetPolicy,
}

impl TargetField {
    /// mecmcp-compat: method TargetField::scalar https://github.com/fastrevmd-lab/mecmcp/issues/142
    pub(crate) const fn scalar(name: &'static str) -> Self {
        Self {
            name,
            shape: TargetValueShape::Scalar,
            malformed: MalformedTargetPolicy::Deny,
        }
    }
}

#[derive(Debug, Clone)]
/// mecmcp-compat: type mecmcp_transport::ToolScopePreflight https://github.com/fastrevmd-lab/mecmcp/issues/113
pub(crate) struct ToolScopePreflight {
    write_tools: &'static [&'static str],
    target_fields: Vec<TargetField>,
    malformed_arguments: MalformedArgumentsPolicy,
}

impl ToolScopePreflight {
    /// mecmcp-compat: method ToolScopePreflight::new https://github.com/fastrevmd-lab/mecmcp/issues/143
    pub(crate) fn new(
        write_tools: &'static [&'static str],
        target_fields: impl IntoIterator<Item = TargetField>,
        malformed_arguments: MalformedArgumentsPolicy,
    ) -> Self {
        Self {
            write_tools,
            target_fields: target_fields.into_iter().collect(),
            malformed_arguments,
        }
    }

    /// mecmcp-compat: method ToolScopePreflight::request_exceeds_scope https://github.com/fastrevmd-lab/mecmcp/issues/144
    fn request_exceeds_scope(&self, value: &Value, caller: CallerScopes<'_>) -> bool {
        if value.get("method").and_then(Value::as_str) != Some("tools/call") {
            return false;
        }
        let Some(params) = value.get("params") else {
            return false;
        };
        let Some(tool) = params.get("name").and_then(Value::as_str) else {
            return false;
        };
        if !caller.tools.allows_tool(tool, self.write_tools) {
            return true;
        }
        let Some(arguments_value) = params.get("arguments") else {
            return false;
        };
        let Some(arguments) = arguments_value.as_object() else {
            return self.malformed_arguments == MalformedArgumentsPolicy::Deny;
        };
        self.target_fields.iter().any(|field| {
            arguments
                .get(field.name)
                .is_some_and(|value| !target_value_in_scope(value, *field, caller.devices))
        })
    }
}

impl ScopePreflight for ToolScopePreflight {
    /// mecmcp-compat: method ToolScopePreflight::check https://github.com/fastrevmd-lab/mecmcp/issues/145
    fn check(&self, body: &[u8], caller: CallerScopes<'_>) -> Result<(), String> {
        if body.is_empty() {
            return Ok(());
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return Ok(());
        };
        let denied = match value {
            Value::Array(values) => values
                .iter()
                .any(|value| self.request_exceeds_scope(value, caller.clone())),
            value => self.request_exceeds_scope(&value, caller),
        };
        if denied {
            Err("insufficient_scope".to_owned())
        } else {
            Ok(())
        }
    }
}

/// mecmcp-compat: function mecmcp_transport::target_value_in_scope https://github.com/fastrevmd-lab/mecmcp/issues/146
fn target_value_in_scope(value: &Value, field: TargetField, devices: &ScopeSet) -> bool {
    let valid = match field.shape {
        TargetValueShape::Scalar => value.as_str().is_some_and(|name| devices.allows(name)),
        TargetValueShape::NonEmptyArray => value.as_array().is_some_and(|names| {
            !names.is_empty()
                && names
                    .iter()
                    .all(|name| name.as_str().is_some_and(|name| devices.allows(name)))
        }),
    };
    valid
        || field.malformed == MalformedTargetPolicy::Ignore && !value_has_shape(value, field.shape)
}

/// mecmcp-compat: function mecmcp_transport::value_has_shape https://github.com/fastrevmd-lab/mecmcp/issues/147
fn value_has_shape(value: &Value, shape: TargetValueShape) -> bool {
    match shape {
        TargetValueShape::Scalar => value.is_string(),
        TargetValueShape::NonEmptyArray => value
            .as_array()
            .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller_with(devices: ScopeSet, tools: ScopeSet) -> CallerScopes<'static> {
        // Leak the ScopeSets so they have 'static lifetime for testing
        let devices = Box::leak(Box::new(devices));
        let tools = Box::leak(Box::new(tools));
        CallerScopes {
            token_name: "reader",
            devices,
            tools,
        }
    }

    #[test]
    fn preflight_rejects_out_of_scope_tenant_and_write_wildcard() {
        let preflight = ToolScopePreflight::new(
            crate::WRITE_TOOLS,
            [TargetField::scalar("tenant")],
            MalformedArgumentsPolicy::Deny,
        );
        let caller = caller_with(
            ScopeSet::Allowlist(vec!["production".to_owned()]),
            ScopeSet::Wildcard,
        );
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_sdc_tenant_scope","arguments":{"tenant":"other"}}}"#,
                caller.clone(),
            )
            .is_err());
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"apply_sdc_change_set","arguments":{"tenant":"production"}}}"#,
                caller,
            )
            .is_err());
    }
}
