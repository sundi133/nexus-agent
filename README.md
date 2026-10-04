# Nexus Agent

Nexus Agent is the endpoint collection and policy-enforcement foundation for Votal.

## Current implementation

This repository is starting from a minimal baseline. The first milestone adds a portable Rust policy core and a JSON-lines evaluation CLI that can be tested without privileged endpoint APIs.

- `core/`: shared event model, deterministic policy evaluation, ransomware-behavior scoring, and CLI.
- `schemas/`: versioned JSON schemas for event and policy contracts.
- `platforms/`: native adapter design for macOS, Windows, and Linux.

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
