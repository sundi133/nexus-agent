# Nexus Agent

Nexus Agent is the endpoint collection and policy-enforcement foundation for Votal.

## Current implementation

Nexus Agent now contains a shared signed-policy/detection core, a managed control-plane runtime, and native platform adapters.

- `core/`: Ed25519-verified policy engine, anti-rollback primitives, health contracts, ransomware behavior correlation, response planning, C ABI, and policy signing utility.
- `runtime/`: HTTPS policy retrieval, local verification, health/events upload, credential rotation, bounded offline spool, and last-known-good activation.
- `platforms/macos/`: Endpoint Security collection/enforcement, packaged system extension, Network Extension filtering, health reporting, and guarded ransomware containment.
- `platforms/windows/`: Windows service, process/file ETW, WFP network enforcement, health reporting, and guarded ransomware containment.
- `platforms/linux/`: fanotify telemetry/permission harnesses, nftables enforcement, health reporting, and guarded ransomware containment.
- `schemas/`: versioned event, policy, health, and runtime configuration contracts.

## Quick start

Install Rust stable, then run:

```sh
cd core
cargo test
cargo run -- evaluate examples/policy.json examples/event.json
```

The CLI is a policy-engine prototype. It does **not** install an endpoint agent or block operating-system actions. Native enforcement must be implemented and tested using each OS's supported security APIs.

## Security posture

- Default policy behavior is allow when no rule matches; deployments must define their intended default posture explicitly.
- Audit mode never enforces a deny decision.
- Do not call remote services or an LLM from synchronous OS authorization callbacks.
- Treat event paths, hostnames, PIDs, and command-line data as untrusted and potentially sensitive.
- Do not enable fleet-wide blocking until policy signatures, rollback, health reporting, and OS-specific integration tests are in place.

See [platform implementation notes](platforms/README.md) and [security design](docs/SECURITY_DESIGN.md).
