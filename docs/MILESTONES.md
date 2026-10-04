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
Status: in progress.

- per-process bounded time-window feature aggregation
- bounded producer/consumer queue
- dropped-event/latency counters
- event normalization into shared schema
- synthetic replay tests

## M3 — macOS narrow enforcement
Planned.

- AUTH_EXEC only at first
- local deterministic policy decisions
- explicit deadline/fallback semantics
- audit/shadow mode
- enforcement outcome telemetry
- emergency rollback/kill switch

## M4 — macOS production packaging
Planned.

- Endpoint Security system extension
- signed/notarized host application
- policy signature verification and secure enrollment
- health/status reporting
- MDM profiles
- Network Extension content filtering

## M5 — Windows
Planned after macOS enforcement semantics stabilize.

- Windows service
- ETW telemetry
- WFP network enforcement
- filesystem minifilter only for controls that require it
- signed installer/driver pipeline

## M6 — Linux
Planned after shared enforcement semantics stabilize.

- Rust daemon
- eBPF telemetry with explicit kernel support matrix
- fanotify permission events
- nftables network policy
- optional BPF LSM where supported
