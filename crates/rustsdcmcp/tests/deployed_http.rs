//! Temporary standards-aware verifier for deployed Streamable HTTP MCP.

mod common;

use common::{McpHttpClient, SafeTransportError};
use serde_json::json;
use std::env;

const EXPECTED_TOOLS: [&str; 14] = [
    "get_sdc_change_set",
    "get_sdc_deploy_device_result",
    "get_sdc_deploy_status",
    "get_sdc_device",
    "get_sdc_firewall_policy",
    "get_sdc_nat_policy",
    "get_sdc_preview_device_result",
    "get_sdc_preview_status",
    "get_sdc_resource",
    "get_sdc_tenant_scope",
    "list_sdc_devices",
    "list_sdc_firewall_policies",
    "list_sdc_nat_policies",
    "list_sdc_resources",
];
const WRITE_TOOLS: [&str; 3] = [
    "prepare_sdc_policy_deploy",
    "approve_sdc_change_set",
    "apply_sdc_change_set",
];

#[tokio::test]
#[ignore = "requires an explicitly reviewed deployed endpoint and read-only bearer"]
async fn verifies_deployed_read_only_mcp_surface() -> Result<(), SafeTransportError> {
    let url = env::var("RUSTSDCMCP_VERIFY_URL")
        .map_err(|_| SafeTransportError::invalid_configuration())?;
    let bearer = env::var("RUSTSDCMCP_VERIFY_BEARER")
        .map_err(|_| SafeTransportError::invalid_configuration())?;
    let mut client = McpHttpClient::new(&url, Some(&bearer))?;

    let verification = async {
        client.initialize("2025-03-26").await?;
        client.notify_initialized().await?;

        let tools_response = client.list_tools().await?;
        let tools = tools_response
            .pointer("/result/tools")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(SafeTransportError::invalid_contract)?;
        let mut names = tools
            .iter()
            .map(|tool| {
                tool.get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(SafeTransportError::invalid_contract)
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort_unstable();

        if WRITE_TOOLS.iter().any(|write| names.contains(write)) {
            return Err(SafeTransportError::invalid_contract());
        }
        if names != EXPECTED_TOOLS {
            return Err(SafeTransportError::invalid_contract());
        }

        let call_response = client
            .call_tool("get_sdc_tenant_scope", json!({"tenant": "production"}))
            .await?;
        if call_response
            .get("error")
            .is_some_and(|error| !error.is_null())
            || call_response
                .pointer("/result/isError")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
        {
            return Err(SafeTransportError::invalid_contract());
        }

        Ok(())
    }
    .await;

    let cleanup = client.close().await;
    verification?;
    cleanup?;

    println!("deployed_mcp=verified tools=14 write_tools=absent tenant_scope=passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::common::{BodyAccumulator, parse_mcp_response};
    use serde_json::json;

    #[test]
    fn parses_normal_json_response() {
        let payload = parse_mcp_response(
            Some("application/json; charset=utf-8"),
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
            1,
        )
        .expect("JSON response");

        assert_eq!(
            payload,
            json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}})
        );
    }

    #[test]
    fn skips_empty_and_non_json_sse_priming_events() {
        let payload = parse_mcp_response(
            Some("text/event-stream"),
            b": keep-alive\n\n\
              data:\n\n\
              event: priming\n\
              data: not-json\n\n\
              event: message\n\
              data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n",
            2,
        )
        .expect("JSON SSE payload");

        assert_eq!(payload, json!({"jsonrpc": "2.0", "id": 2, "result": {}}));
    }

    #[test]
    fn joins_multiline_sse_data_fields_with_newlines() {
        let payload = parse_mcp_response(
            Some("text/event-stream"),
            b"data: {\"jsonrpc\":\"2.0\",\n\
              data: \"id\":3,\"result\":{\"ok\":true}}\n\n",
            3,
        )
        .expect("multiline JSON SSE payload");

        assert_eq!(
            payload,
            json!({"jsonrpc": "2.0", "id": 3, "result": {"ok": true}})
        );
    }

    #[test]
    fn rejects_malformed_or_missing_json_payload() {
        assert_eq!(
            parse_mcp_response(Some("application/json"), b"{broken", 1)
                .expect_err("malformed JSON must fail")
                .to_string(),
            "MCP response did not contain a valid JSON payload"
        );
        assert_eq!(
            parse_mcp_response(Some("text/event-stream"), b": only a comment\n\n", 1)
                .expect_err("missing JSON must fail")
                .to_string(),
            "MCP response did not contain a valid JSON payload"
        );
    }

    #[test]
    fn rejects_unterminated_sse_record() {
        assert_eq!(
            parse_mcp_response(
                Some("text/event-stream"),
                b"data: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{}}",
                4,
            )
            .expect_err("unterminated SSE record must fail")
            .to_string(),
            "MCP response did not contain a valid JSON payload"
        );
    }

    #[test]
    fn rejects_mismatched_json_rpc_response() {
        assert_eq!(
            parse_mcp_response(
                Some("application/json"),
                br#"{"jsonrpc":"2.0","id":99,"result":{}}"#,
                5,
            )
            .expect_err("mismatched JSON-RPC id must fail")
            .to_string(),
            "MCP response did not contain a valid JSON payload"
        );
    }

    #[test]
    fn skips_unrelated_json_sse_events_before_matching_response() {
        let payload = parse_mcp_response(
            Some("text/event-stream"),
            b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n\
              data: {\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"sampling/createMessage\",\"params\":{}}\n\n\
              data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n\
              data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"ok\":true}}\n\n",
            5,
        )
        .expect("matching JSON-RPC response");

        assert_eq!(
            payload,
            json!({"jsonrpc": "2.0", "id": 5, "result": {"ok": true}})
        );
    }

    #[test]
    fn enforces_response_size_while_accumulating_chunks() {
        let mut body = BodyAccumulator::new(5);

        body.push(b"123").expect("first chunk fits");
        assert_eq!(
            body.push(b"456")
                .expect_err("second chunk exceeds the bound")
                .to_string(),
            "MCP response exceeded the configured size limit"
        );
        assert_eq!(body.into_bytes(), b"123");
    }
}
