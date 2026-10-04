use nexus_agent_core::{AgentActionEvent, AgentActionKind};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn normalize_mcp_action(
    server_id: &str,
    device_id: &str,
    message: &Value,
    event_prefix: &str,
) -> Option<AgentActionEvent> {
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }

    let method = message.get("method").and_then(Value::as_str)?;
    let params = message.get("params");

    let (kind, tool_name, operation, resource) = match method {
        "tools/call" => {
            let name = params
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)?
                .to_string();
            (
                AgentActionKind::McpToolCall,
                Some(name),
                "call".to_string(),
                None,
            )
        }
        "resources/read" => {
            let uri = params
                .and_then(|value| value.get("uri"))
                .and_then(Value::as_str)
                .map(str::to_string);
            (
                AgentActionKind::McpResourceRead,
                None,
                "read".to_string(),
                uri,
            )
        }
        _ => return None,
    };

    let sequence = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1;
    let now = OffsetDateTime::now_utc();
    let timestamp = now
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    Some(AgentActionEvent {
        event_id: format!("{event_prefix}-{}-{sequence}", std::process::id()),
        timestamp,
        device_id: device_id.to_string(),
        pid: Some(std::process::id()),
        agent_id: None,
        session_id: None,
        kind,
        mcp_server: Some(server_id.to_string()),
        tool_name,
        operation,
        resource,
        risk_tags: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_call_does_not_capture_arguments() {
        let message = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "path": "/secret",
                    "content": "must-not-leak"
                }
            }
        });

        let event = normalize_mcp_action("filesystem", "device", &message, "test").unwrap();
        assert_eq!(event.tool_name.as_deref(), Some("write_file"));
        assert!(event.resource.is_none());

        let encoded = serde_json::to_string(&event).unwrap();
        assert!(!encoded.contains("must-not-leak"));
        assert!(!encoded.contains("/secret"));
    }

    #[test]
    fn resource_read_keeps_only_uri() {
        let message = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "r1",
            "method": "resources/read",
            "params": {"uri": "file:///docs/manual.pdf"}
        });

        let event = normalize_mcp_action("docs", "device", &message, "test").unwrap();
        assert_eq!(event.kind, AgentActionKind::McpResourceRead);
        assert_eq!(event.resource.as_deref(), Some("file:///docs/manual.pdf"));
    }

    #[test]
    fn other_methods_are_not_policy_intercepted() {
        let message = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        assert!(normalize_mcp_action("server", "device", &message, "test").is_none());
    }
}
