# Ransomware response policy

Ransomware detection and response are intentionally separate.

The detector produces a score and supporting signals. A signed policy must separately opt into a response.

Example:

```json
{
  "ransomware_response": {
    "mode": "shadow",
    "action": "terminate_process",
    "min_score": 90,
    "require_suspicious_process_context": true
  }
}
```

## Modes

- `disabled`: no response plan is produced.
- `shadow`: records what the agent would do, but does not take the destructive action.
- `enforce`: permits the configured platform response after all response predicates match.

## Actions

- `alert`
- `terminate_process`
- `network_isolate`
- `terminate_and_network_isolate`

## Safety invariant

Signed policy validation rejects destructive process-termination response in `enforce` mode unless:

- `min_score >= 90`; and
- `require_suspicious_process_context = true`.

This prevents a simple high file-count heuristic from being sufficient by itself to terminate a process.

The default remains no automatic containment. Roll out `shadow` first, validate false positives against enterprise workloads, then enable narrowly scoped enforcement.


## Platform containment switches

The current platform executors implement only `terminate_process`.

Containment can be locally disabled without changing the signed policy:

- Windows: create `C:\\ProgramData\\Votal\\Nexus\\disable-containment`
- Linux: create `/var/lib/votal/nexus/disable-containment`
- macOS: create `/Library/Application Support/Votal/Nexus/disable-containment`

macOS also uses the existing runtime kill switch: `SIGUSR1` forces allow/no-containment and `SIGUSR2` resumes configured policy.

The executors refuse protected/self targets:

- Windows: PID 0–4 and the Nexus service PID
- Linux/macOS: PID 0/1 and the Nexus agent/extension PID

Unsupported response actions are reported but not partially executed. In particular, `terminate_and_network_isolate` does **not** terminate a process unless the platform can satisfy the complete configured response semantics in a future implementation.
