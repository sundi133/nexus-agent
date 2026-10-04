# macOS adapter

This directory contains the first native Nexus Agent adapter.

## Milestone 1: Endpoint Security audit collector

The collector subscribes to process and filesystem **NOTIFY** events and emits a small normalized JSON record to stdout. It intentionally does not authorize or block operations yet.

### Requirements

- macOS 13 or later for the initial supported baseline.
- Xcode/Apple Clang.
- An Apple-approved Endpoint Security entitlement for deployment.
- Run from a properly signed system extension/app in production. A command-line executable is useful only for local API integration development.

### Build the development collector

```sh
cd platforms/macos
make
sudo ./build/nexus-es-collector
```

Without the required entitlement/permissions, `es_new_client` will fail. The collector reports the Endpoint Security error instead of claiming protection is active.

### Events

The first audit milestone subscribes to:

- process exec
- process fork
- process exit
- file create
- file rename
- file unlink

File-write authorization is deliberately deferred to the enforcement milestone because synchronous authorization callbacks need stricter latency and failure semantics.

### Next macOS milestones

1. Send normalized events through the shared policy engine rather than stdout.
2. Add bounded in-memory aggregation for ransomware behavior.
3. Add `AUTH_EXEC` with local deterministic decisions and strict time budgets.
4. Add narrow filesystem authorization only after workload/false-positive tests.
5. Package the collector as an Endpoint Security system extension.
6. Add Network Extension filtering and MDM deployment profiles.
