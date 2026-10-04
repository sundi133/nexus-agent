# Native platform adapters

The portable policy core is not itself an OS enforcement mechanism. Each adapter must translate native events into the versioned event schema and map a validated policy decision to an OS-supported enforcement action.

## macOS

- Native language: Swift, with a small C bridge where needed for Endpoint Security API ergonomics.
- Telemetry and process/file authorization: Endpoint Security system extension.
- Network filtering: Network Extension content filter.
- Distribution: signed/notarized app and extensions; managed deployment through MDM.
- Gate: Apple's Endpoint Security entitlement approval and appropriate Network Extension capability.

## Windows

- Service: Rust or C++ Windows service for enrollment, policy, health, and telemetry.
- Telemetry: ETW where suitable.
- Network enforcement: Windows Filtering Platform (WFP).
- File-system monitoring/enforcement: signed minifilter driver where required.
- Script/antimalware integration: AMSI where applicable.
- Gate: driver signing, supported Windows versions, and enterprise deployment testing. ETW by itself is telemetry, not prevention.

## Linux

- Service: Rust userspace daemon.
- Telemetry: eBPF through libbpf/CO-RE where supported.
- Filesystem authorization: fanotify permission events for supported operations.
- Additional enforcement: BPF LSM where supported and enabled; nftables for network rules.
- Gate: explicitly define supported kernel versions, distribution/kernel configuration, privileges, and fallback behavior.

## Adapter contract

1. Report capabilities at startup; never claim enforcement is active when it is unavailable.
2. Convert native events to the normalized schema and include native event IDs/identity in adapter metadata.
3. Use a bounded queue and expose dropped-event counters.
4. Never call the control plane or an LLM from a synchronous authorization callback.
5. Load only validated, signed policy snapshots; define stale-policy and offline behavior.
6. Audit every enforcement decision, including the native API result.
7. Test fail-open/fail-closed behavior per event class. Do not use a single global default for every operating-system action.
8. Start in audit mode, progress through simulated enforcement, then enable narrow allowlisted blocking after validation.
