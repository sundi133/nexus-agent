# AUTH_EXEC controlled enforcement validation

The enforcement harness is intentionally limited to exact executable-path rules.

## Safety properties

- Policy is loaded before the Endpoint Security client starts.
- Invalid or unreadable policy prevents the enforcement harness from starting.
- No file, network, DNS, or model access occurs from the authorization callback.
- Unknown/missing target data is fail-open.
- `mode=audit` never denies an exec request.
- `SIGUSR1` atomically activates the kill switch and forces subsequent requests to allow.
- `SIGUSR2` turns the kill switch off again.
- Every authorization decision reports local callback latency.

## Test sequence on an isolated entitled macOS device

1. Create a harmless purpose-built executable at `/tmp/nexus-deny-test`.
2. Start with `policy.example.conf` in `mode=audit`.
3. Execute the test binary and confirm the log says `audit_would_deny` while the program starts.
4. Change the policy to `mode=enforce`, restart the harness, and confirm only the test binary is denied.
5. Send `SIGUSR1` to the harness and confirm the same test binary starts again.
6. Send `SIGUSR2` and confirm denial resumes.
7. Record p50/p95/p99 callback latency under process-launch load before widening enforcement.

Do not deny shell, login, launchd, security tooling, MDM, or other system-critical executables during validation.
