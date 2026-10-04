# Build milestones

## M0 — shared core
Status: implemented in PR #1.

- normalized event/policy contracts
- deterministic audit/enforce policy decisions
- baseline ransomware feature scoring
- Rust unit tests and CI

## M1 — macOS audit collector
Status: implemented in PR #1; native device validation still required.

- Endpoint Security client startup/error reporting
- process exec/fork/exit notifications
- file create/rename/unlink notifications
- no blocking

## M2 — local detection pipeline
Status: implemented in PR #1; native integration/load validation still required.

- per-process bounded time-window feature aggregation
- bounded producer/consumer queue
- dropped-event/latency counters
- event normalization into shared schema
- synthetic replay tests

## M3 — macOS narrow enforcement
Status: development harness implemented; entitled-device validation and production policy authentication still required.

- AUTH_EXEC exact-path enforcement harness
- local deterministic policy decisions
- fail-open fallback semantics and callback-latency telemetry
- audit/shadow mode
- enforcement outcome telemetry
- atomic emergency kill switch via signal

## M4 — macOS production packaging
Status: host application, Endpoint Security system extension, signed-policy verification, anti-rollback, health reporting, Network Extension content filtering, and policy-gated ransomware containment are implemented in the scaffold. Apple entitlement approval, production signing/notarization, and MDM rollout validation remain.

- Endpoint Security system extension
- host application / system-extension activation
- Ed25519 policy verification and anti-rollback watermark
- machine-readable health/status reporting
- Network Extension content filtering
- policy-gated terminate-process ransomware containment
- remaining: production signing/notarization, entitlement approval, MDM profiles and device validation

## M5 — Windows
Status: ETW process + file telemetry, unique-path ransomware correlation, signed-policy classification, health reporting, anti-rollback watermark, narrow dynamic WFP enforcement, and policy-gated terminate-process ransomware containment are implemented. General process-create blocking, broader network policy, installer/signing, and optional kernel components remain.

- Windows service
- ETW telemetry
- WFP network enforcement
- filesystem minifilter only for controls that require it
- signed installer/driver pipeline

## M6 — Linux
Status: fanotify audit collection, signed-policy classification, permission-event shadow/controlled enforcement harnesses, ransomware unique-path correlation, health reporting, anti-rollback watermark, signed-policy nftables lease enforcement, and policy-gated terminate-process ransomware containment are implemented. eBPF telemetry/enforcement and broader distro/kernel validation remain.

- Rust daemon
- eBPF telemetry with explicit kernel support matrix
- fanotify permission events
- nftables network policy
- optional BPF LSM where supported


## Cross-platform ransomware detection
Status: behavior correlation is wired on macOS Endpoint Security, Windows Kernel-File ETW, and Linux fanotify.

- true unique-path modification tracking per process/window
- rename-rate signal
- bounded process cardinality and expiry
- repeated writes to one file do not inflate unique-path count
- execution-policy context is an independent signal

## Cross-platform ransomware response
Status: signed response policy and guarded terminate-process containment are implemented across macOS, Windows, and Linux.

- disabled / shadow / enforce response modes
- response score threshold and independent suspicious-process-context requirement
- destructive enforce-mode policy is rejected unless min_score >= 90 and suspicious context is required
- local containment-disable switches and self/system PID guards
- only `terminate_process` is currently executable as a ransomware response
- `network_isolate` and combined response actions remain non-destructive/unsupported until dedicated isolation semantics are implemented
