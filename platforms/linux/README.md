# Linux adapter

The first Linux milestone is an audit-only `fanotify` collector.

## Current behavior

- Initializes `fanotify` in notification mode.
- Marks the root mount for executable-open and completed-write notifications.
- Converts executable opens to shared `process_exec` events.
- Converts close-after-write events to shared `file_write` events.
- Uses `/etc/machine-id` as the bootstrap device identifier.
- Writes JSON Lines to `/var/lib/votal/nexus/events.jsonl`.
- Does not block filesystem or execution operations.
- Loads `/var/lib/votal/nexus/policy.signed.json` only when the pinned Ed25519 public key is configured.
- Evaluates collected events through the shared Rust policy core and records `would_deny` in **shadow** mode.

## Build

```sh
cargo build --release --manifest-path platforms/linux/Cargo.toml
```

The collector needs elevated privileges/capabilities for mount-wide `fanotify` monitoring. Kernel and distribution behavior must be validated before defining the final support matrix.

## systemd

A starter unit is provided as `nexus-agent.service`. For a test host:

```sh
sudo install -d /opt/votal/nexus
sudo install -m 0755 target/release/nexus-agent-linux /opt/votal/nexus/
sudo install -m 0644 platforms/linux/nexus-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nexus-agent
```

## Next Linux milestones

1. Add bounded telemetry queueing and health counters.
2. Replace the development zero trust-root placeholder with the production Ed25519 public key and add last-known-good policy reload.
3. Introduce `FAN_OPEN_EXEC_PERM` in shadow/allow mode first.
4. Add narrow local allow/deny responses only after latency and workload testing.
5. Add eBPF process/network telemetry where the supported kernel permits it.
6. Add nftables/eBPF network enforcement behind explicit capability checks.
7. Define kernel/distribution fallback behavior instead of claiming unsupported enforcement is active.
