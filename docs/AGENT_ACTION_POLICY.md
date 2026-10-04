# MCP and AI-agent action authorization

Nexus Agent can make deterministic local allow/alert/deny decisions for normalized AI-agent actions submitted to the authenticated loopback bridge.

## Signed policy rules

Agent-action rules live in the same Ed25519-signed policy bundle as endpoint rules:

```json
{
  "version": 42,
  "mode": "enforce",
  "rules": [],
  "agent_action_rules": [
    {
      "id": "deny-sensitive-filesystem-write",
      "action": "deny",
      "kinds": ["mcp_tool_call"],
      "agent_ids": ["coding-agent"],
      "mcp_servers": ["filesystem"],
      "tool_names": ["write_file"],
      "operations": ["write"],
      "resource_prefixes": ["/etc/", "/Library/"],
      "risk_tags": ["filesystem_write"]
    }
  ]
}
```

All populated selector dimensions must match. Values inside one dimension are alternatives.

For the rule above:

- kind must be `mcp_tool_call`;
- logical agent ID must be `coding-agent`;
- server must be `filesystem`;
- tool must be `write_file`;
- operation must be `write`;
- resource must start with `/etc/` **or** `/Library/`;
- the action must contain at least one configured risk tag.

Empty-selector rules are rejected during signed-policy validation.

## Decision behavior

`mode=enforce` + matching `action=deny` returns HTTP `403` and a decision body similar to:

```json
{
  "action": "deny",
  "rule_id": "deny-sensitive-filesystem-write",
  "reason": "matched agent-action policy",
  "policy_version": 42,
  "would_deny": true
}
```

In `mode=audit`, the same deny rule returns HTTP `200` with `action=alert` and `would_deny=true`.

If no verified policy is loaded, the bridge fails open with `action=allow`, `policy_version=0`, and an explicit reason.

## Local bridge

The bridge listens only on `127.0.0.1` and requires the independently provisioned local-ingest bearer token.

Example request:

```sh
curl -sS \
  -H "Authorization: Bearer $NEXUS_LOCAL_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "event_id":"agent-evt-1",
    "timestamp":"2026-10-04T00:00:00Z",
    "device_id":"device-1",
    "pid":4242,
    "agent_id":"coding-agent",
    "session_id":"session-7",
    "kind":"mcp_tool_call",
    "mcp_server":"filesystem",
    "tool_name":"write_file",
    "operation":"write",
    "resource":"/etc/hosts",
    "risk_tags":["filesystem_write"]
  }' \
  http://127.0.0.1:8765/v1/agent-actions
```

The bridge does not call an LLM or the control plane before responding. The event and local decision are added to the durable endpoint spool for later audit upload.

## Integration contract for MCP/agent runtimes

A producer that wants blocking must call the bridge **before** invoking the sensitive tool/action:

1. Normalize the intended action.
2. POST it to the local bridge.
3. On `200` + `allow`, proceed.
4. On `200` + `alert`, proceed but surface/audit the alert.
5. On `403` + `deny`, do not invoke the tool.
6. Treat transport/unavailable errors according to that producer's explicit fail-open/fail-closed policy. Nexus itself does not pretend an unavailable bridge made a deny decision.

The producer must not submit raw prompts, secrets, full tool arguments, or file contents by default. Send the minimum normalized metadata needed for policy matching.


## Credential-bound agent identity

For production agent-ID policy, configure one token per local producer instead of the legacy shared token:

```json
{
  "local_ingest_port": 8765,
  "local_ingest_token_file": null,
  "local_ingest_producers": [
    {
      "agent_id": "coding-agent",
      "token_file": "/var/lib/votal/nexus/producers/coding-agent.token"
    },
    {
      "agent_id": "browser-agent",
      "token_file": "/var/lib/votal/nexus/producers/browser-agent.token"
    }
  ]
}
```

The runtime rejects duplicate configured agent IDs and duplicate token values. After a token authenticates, its configured `agent_id` is authoritative. If a request claims a different `agent_id`, the bridge returns `403` and does not evaluate the action under the spoofed identity.

The older `local_ingest_token_file` mode remains available for compatibility, but it authenticates bridge access only. In that mode the runtime clears any request-supplied `agent_id` before policy evaluation, so rules containing `agent_ids` cannot be satisfied by self-assertion.

Credential binding is stronger than trusting request JSON, but it is not yet OS/process attestation. Protect each producer token with platform ACLs and give it only to the intended runtime/process. A later identity layer should bind producers to OS code-signing/process identity or another local attestation mechanism.


## Kernel peer attestation on Unix

For Linux/macOS, the strongest local bridge mode uses a Unix-domain socket instead of loopback TCP:

```json
{
  "local_ingest_port": null,
  "local_ingest_socket_path": "/run/votal/nexus/agent-actions.sock",
  "local_ingest_token_file": null,
  "local_ingest_producers": [
    {
      "agent_id": "coding-agent",
      "token_file": "/var/lib/votal/nexus/producers/coding-agent.token",
      "expected_uid": 1000,
      "executable_paths": ["/usr/local/bin/coding-agent"]
    }
  ]
}
```

The socket is created with mode `0660`. The token still proves the producer credential, while the kernel peer credentials add an independent local identity signal.

On Linux, Nexus reads `SO_PEERCRED` and records the peer PID, UID, GID, and `/proc/<pid>/exe`. If `expected_uid` or `executable_paths` are configured, the request is rejected unless the kernel-derived peer evidence matches. A request-supplied PID that disagrees with the kernel PID is rejected; otherwise the event PID is replaced with the kernel PID before policy evaluation.

On macOS, the current Unix path uses peer effective UID/GID from the kernel. `expected_uid` is enforceable there. Process executable/code-signature attestation is not yet implemented on macOS, so configuring `executable_paths` for macOS producers will intentionally fail authentication rather than silently downgrading the check.

Loopback TCP remains for compatibility. It does not provide kernel peer process identity and therefore must not be described as OS/process attestation.
