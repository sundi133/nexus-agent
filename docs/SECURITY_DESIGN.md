# Security design and rollout guardrails

## Threat model

The agent is intended to observe endpoint behavior, identify suspicious process/file/network activity, and enforce explicitly configured enterprise policy. It is not a guarantee that all malware or ransomware can be detected or blocked.

## Policy safety

- Policies must be authenticated and integrity-checked before activation. This repository's initial JSON CLI does not yet implement signature verification.
- Validate schema, rule count, string lengths, policy version, and expiration before accepting a bundle.
- Keep the last-known-good bundle and support administrator-controlled rollback.
- Define rule precedence and conflict handling before adding broad rules.
- Never block solely because a process modifies many files; correlate multiple signals and calibrate against real enterprise workloads.
- A policy decision is not proof that the OS successfully enforced the action. Record requested and actual outcomes separately.

## Runtime safety

- No network requests, disk I/O, or model inference in synchronous authorization callbacks.
- Use bounded queues, explicit time budgets, and observable dropped-event counters.
- Minimize collection of command-line arguments, file paths, user data, and network metadata.
- Protect device identity and enrollment credentials with OS-appropriate secure storage.
- Separate telemetry upload failures from local policy enforcement.
- Include health reporting for API permissions, extension/provider status, policy version, and last successful check-in.

## Rollout

1. Unit tests and event replay.
2. Audit-only collection on developer test devices.
3. Simulated enforcement with alert-only outcomes.
4. Narrow allowlisted blocking on a dedicated test fleet.
5. Staged enterprise rollout with health gates and rollback.
6. Expand coverage only after false-positive, latency, and reliability targets are measured.

## Known prototype limitations

- The policy engine matches exact executable path strings and case-insensitive destination host strings; it does not yet canonicalize paths, verify code signatures, resolve DNS, or handle IP/CIDR policy.
- The ransomware scoring function is a test scaffold, not a production classifier.
- The CLI does not install drivers/system extensions, collect live endpoint events, verify signed policies, or enforce OS actions.
