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
Planned.

- Endpoint Security system extension
- signed/notarized host application
- policy signature verification and secure enrollment
- health/status reporting
- MDM profiles
- Network Extension content filtering

## M5 — Windows
Status: ETW process telemetry, signed-policy shadow classification, health reporting, anti-rollback watermark, and narrow dynamic WFP enforcement are implemented. Process blocking and broader network policy remain.

- Windows service
- ETW telemetry
- WFP network enforcement
- filesystem minifilter only for controls that require it
- signed installer/driver pipeline

## M6 — Linux
Status: fanotify audit collection, signed-policy shadow classification, permission-event shadow/controlled enforcement harnesses, ransomware unique-path correlation, health reporting, anti-rollback watermark, and controlled nftables blocking are implemented. Signed-policy nftables orchestration and eBPF remain.

- Rust daemon
- eBPF telemetry with explicit kernel support matrix
- fanotify permission events
- nftables network policy
- optional BPF LSM where supported


## Cross-platform ransomware detection
Status: detection pipeline active in macOS packaged extension and Linux audit collector; Windows file-I/O telemetry remains.

- true unique-path modification tracking per process/window
- rename-rate signal
- bounded process cardinality and expiry
- repeated writes to one file do not inflate unique-path count
- high/critical findings are detection-only; no heuristic-only process termination
