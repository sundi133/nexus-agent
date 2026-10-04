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
Status: ETW process + file telemetry, unique-path ransomware correlation, signed-policy classification, health reporting, anti-rollback watermark, multi-rule dynamic WFP enforcement with app scoping, live policy reload, LocalService managed-runtime packaging, and policy-gated terminate-process ransomware containment are implemented. General process-create blocking, MSI/code-signing, and optional kernel components remain.

- Windows service
- ETW telemetry
- WFP network enforcement
- filesystem minifilter only for controls that require it
- signed installer/driver pipeline

## M6 — Linux
Status: fanotify audit collection, signed-policy classification, permission-event shadow/controlled enforcement harnesses, ransomware unique-path correlation, health reporting, anti-rollback watermark, multi-destination nftables lease enforcement with live policy reload/last-known-good retention, non-root managed-runtime packaging, and policy-gated terminate-process ransomware containment are implemented. eBPF telemetry/enforcement and broader distro/kernel validation remain.

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


## M7 — managed control-plane runtime
Status: implemented as a separate Rust sidecar with Linux, Windows, and macOS deployment scaffolds; production control-plane integration and fleet validation remain.

- HTTPS-only policy, health, and telemetry transport
- bearer token loaded from a local protected file
- Ed25519 policy verification before atomic activation
- version watermark anti-rollback
- durable bounded disk spool with acknowledgement after successful upload
- JSONL collector tailing with persisted offset and file-replacement anchor detection
- at-least-once telemetry semantics
- runtime spool/transport health merged into endpoint health
- Windows SCM service under LocalService
- Linux systemd service under dedicated non-root identity
- macOS LaunchDaemon under dedicated service identity
- remaining: production enrollment/device identity issuance, token rotation, server-side deduplication and fleet rollout validation


## M8 — AI agent / MCP action telemetry
Status: normalized event model, authenticated localhost bridge, signed MCP/tool/action selectors, synchronous local allow/alert/deny decisions, decision audit spooling, hot policy refresh, generic stdio enforcement, and Streamable HTTP enforcement are implemented. SDK-native integrations and platform publisher/code-signature identity remain.

- normalized `AgentActionEvent` for MCP tool calls, resource reads, agent commands, browser actions, network requests, and file operations
- strict size/cardinality validation and JSON schema
- loopback-only `POST /v1/agent-actions` bridge
- separate local bearer token with constant-time comparison
- 64 KiB request-body cap and 16 KiB header cap
- no raw prompt or raw tool-argument capture by default
- accepted actions use the same durable spool/control-plane event path as endpoint telemetry
- signed policy selectors for MCP server, tool, action kind, operation, resource prefix, and risk tags
- synchronous local allow/alert/deny response without control-plane or model latency
- credential-bound producer identities with anti-spoofing
- Linux Unix-socket kernel peer attestation (PID/UID/GID/executable path)
- macOS Unix-socket peer PID/UID/GID/executable-path attestation
- Windows named-pipe client PID/executable attestation
- executable SHA-256 pinning on Linux, macOS, and Windows attested producer paths
- generic MCP stdio enforcement proxy for `tools/call` and `resources/read`, fail-closed by default
- Streamable HTTP reverse proxy with local authorization before upstream forwarding and streaming response support
- end-to-end tests proving denied tool calls do not reach the upstream MCP server
- remaining: macOS code-signature identity, Windows publisher/AuthentiCode identity, SDK-native MCP adapters, and broader agent-runtime integrations


## Live policy/control-plane status

- Signed policy versions are immutable: identical same-version envelopes are idempotent; different content reusing a version is rejected.
- Windows and Linux check the persisted policy watermark and stage native network enforcement before activation.
- Failed/unsupported native staging retains the last-known-good policy and enforcement state.
- macOS checks the policy watermark every second and also supports an explicit SIGHUP reload check.
- The Ed25519 public trust root is provisioned as a protected base64 file by each platform installer; no private signing key is shipped to endpoints.
- The managed runtime handles HTTPS policy fetch, health upload, and durable at-least-once telemetry spooling outside privileged authorization callbacks.
