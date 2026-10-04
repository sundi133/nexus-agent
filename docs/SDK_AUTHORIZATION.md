# SDK-native MCP authorization

The runtime crate exposes `AgentActionClient` for agent/MCP runtimes that can call Nexus directly instead of using the stdio or Streamable HTTP proxies.

## Rust example

```rust
use nexus_agent_runtime::{AgentActionClient, LocalAuthorizationTarget};

let client = AgentActionClient::from_token_file(
    LocalAuthorizationTarget::Unix("/run/votal/nexus/agent-actions.sock".into()),
    "device-123",
    std::path::Path::new("/var/lib/votal/nexus/producers/coding-agent.token"),
)?;

let decision = client.authorize_mcp_tool(
    "filesystem",
    "write_file",
    Some("session-7"),
    &["filesystem_write".to_string()],
)?;

if matches!(decision.action, nexus_agent_core::DecisionAction::Deny) {
    // Do not invoke the MCP tool.
}
```

Windows callers use `LocalAuthorizationTarget::WindowsPipe("VotalNexusAgentActions".into())`. Loopback TCP is available for compatibility but does not provide process attestation.

## Security contract

- The SDK-generated event includes the current process PID but does not self-assert `agent_id`.
- The local bridge binds authoritative agent identity from the producer credential.
- Attested Unix/named-pipe transports can additionally validate peer PID, UID, executable path, and optional executable SHA-256 pins.
- Policy evaluation is local and deterministic; no LLM/control-plane request is made before the decision.
- The caller must enforce `deny` by not invoking the protected tool/action.
- Transport errors are returned to the caller; the SDK does not silently choose fail-open or fail-closed.

## Resource reads

`authorize_mcp_resource_read(server_id, resource_uri, session_id, risk_tags)` applies the same signed policy model for MCP resource reads.

For other action types, construct a validated `AgentActionEvent` and call `client.authorize(&event)`.
