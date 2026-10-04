# Local producer attestation deployment

For MCP/agent-action enforcement, prefer an OS-native local IPC transport that can identify the connecting process.

## Linux

Use a Unix-domain socket:

```json
{
  "local_ingest_port": null,
  "local_ingest_socket_path": "/run/votal/nexus/agent-actions.sock",
  "local_ingest_pipe_name": null,
  "local_ingest_token_file": null,
  "local_ingest_producers": [
    {
      "agent_id": "coding-agent",
      "token_file": "/var/lib/votal/nexus/producers/coding-agent.token",
      "expected_uid": 1001,
      "executable_paths": ["/opt/company/coding-agent"],
      "executable_sha256": []
    }
  ]
}
```

The runtime validates kernel peer credentials with `SO_PEERCRED`, derives the peer PID, resolves `/proc/<pid>/exe`, and can optionally pin a SHA-256 digest of the executable.

## macOS

Use a Unix-domain socket:

```json
{
  "local_ingest_port": null,
  "local_ingest_socket_path": "/Library/Application Support/Votal/Nexus/agent-actions.sock",
  "local_ingest_pipe_name": null,
  "local_ingest_token_file": null,
  "local_ingest_producers": [
    {
      "agent_id": "coding-agent",
      "token_file": "/Library/Application Support/Votal/Nexus/producers/coding-agent.token",
      "expected_uid": 501,
      "executable_paths": ["/Applications/CodingAgent.app/Contents/MacOS/CodingAgent"],
      "executable_sha256": []
    }
  ]
}
```

The runtime uses peer UID/GID plus the kernel-provided peer PID and resolves the executable path with `proc_pidpath`. Executable hash pinning is supported. Apple code-signing identity validation is a separate future hardening layer.

## Windows

Use a local named pipe:

```json
{
  "local_ingest_port": null,
  "local_ingest_socket_path": null,
  "local_ingest_pipe_name": "VotalNexusAgentActions",
  "local_ingest_token_file": null,
  "local_ingest_producers": [
    {
      "agent_id": "coding-agent",
      "token_file": "C:\\ProgramData\\Votal\\Nexus\\producers\\coding-agent.token",
      "expected_uid": null,
      "executable_paths": ["C:\\Program Files\\Company\\CodingAgent.exe"],
      "executable_sha256": []
    }
  ]
}
```

The runtime rejects remote named-pipe clients, obtains the client PID from the kernel, resolves the executable path, and can optionally pin SHA-256.

## Security properties

- Producer token authenticates the configured logical `agent_id`.
- Kernel peer identity authenticates the local process transport endpoint.
- If a request-supplied PID or agent ID conflicts with attested identity, the request is rejected.
- Path and hash constraints are additional AND conditions.
- Loopback TCP does not establish process identity and should be treated as compatibility mode only.
- Never use a single shared producer token across unrelated agents when `agent_ids` policy selectors matter.

## Recommended rollout

1. Start with credential-bound tokens and attested IPC.
2. Enable path pinning.
3. Enable executable SHA-256 pinning for stable binaries.
4. Add platform code-signature identity when available for update-friendly publisher identity.
5. Only then rely on agent-specific deny policy for high-impact tool actions.
