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
