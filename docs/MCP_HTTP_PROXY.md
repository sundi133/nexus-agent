# MCP Streamable HTTP enforcement proxy

`nexus-mcp-http-proxy` is a local reverse proxy for MCP Streamable HTTP endpoints.

It listens only on loopback, evaluates sensitive JSON-RPC actions against the local Nexus authorization bridge, and forwards the original request upstream only when policy allows it.

## What is intercepted

The proxy currently normalizes and authorizes:

- `tools/call`
- `resources/read`

Other MCP methods such as `initialize`, `ping`, `tools/list`, and `resources/list` pass through unchanged.

The proxy does **not** capture raw prompts or raw tool arguments for policy evaluation. For `tools/call`, only the tool name and normalized metadata are sent to the local authorization bridge. For `resources/read`, only the URI is retained.

## Example

Linux/macOS using the attested Unix socket:

```sh
nexus-mcp-http-proxy \
  --listen 127.0.0.1:9010 \
  --upstream http://127.0.0.1:3000/mcp \
  --server-id filesystem \
  --device-id device-123 \
  --token-file /var/lib/votal/nexus/producers/coding-agent.token \
  --unix /run/votal/nexus/agent-actions.sock \
  --on-unavailable deny
```

Windows using the attested named pipe:

```powershell
nexus-mcp-http-proxy.exe --listen 127.0.0.1:9010 --upstream http://127.0.0.1:3000/mcp --server-id filesystem --device-id device-123 --token-file "C:\\ProgramData\\Votal\\Nexus\\producers\\coding-agent.token" --pipe VotalNexusAgentActions --on-unavailable deny
```

Point the MCP client at:

```text
http://127.0.0.1:9010/mcp
```

## Upstream security

The upstream URL must use HTTPS unless it is loopback HTTP.

For an upstream MCP endpoint that requires a bearer token, use `--upstream-bearer-token-file /path/to/upstream.token`.

The upstream credential is read from a protected local secret file and is not exposed to the MCP client.

## Decision behavior

When policy allows or alerts, the original request is forwarded.

When a protected action is denied, the proxy does not contact upstream and returns a JSON-RPC error with code `-32003`.

Authorization-unavailable behavior is explicit:

- `--on-unavailable deny` — fail closed and return HTTP 503 / JSON-RPC error.
- `--on-unavailable allow` — log the failure and forward upstream.

For production security-sensitive MCP tools, `deny` is the recommended mode.

## Streamable HTTP behavior

The proxy forwards MCP session-related headers including `Mcp-Session-Id`, `Last-Event-ID`, `Accept`, and `Content-Type`.

Upstream response bodies are streamed instead of fully buffered, allowing long-lived SSE responses to remain open.

Request bodies are capped at 4 MiB and active downstream requests are bounded.

## Batch requests

JSON-RPC arrays are inspected element-by-element.

If any protected action is denied, the current implementation rejects the HTTP request based on the first denied action instead of partially forwarding the remaining batch. This avoids accidentally forwarding a prohibited tool call, but it is intentionally conservative.

## Trust boundary

The HTTP proxy itself is not the policy authority. It delegates to the same local verified-policy authorization bridge used by the stdio proxy.

Preferred production chain:

```text
MCP client
   |
   v
Nexus Streamable HTTP proxy
   |
   +--> local attested Nexus authorization bridge
   |        |
   |        +--> verified signed policy
   |
   v
upstream MCP server
```

This keeps policy evaluation local and avoids control-plane or model latency in the authorization path.
