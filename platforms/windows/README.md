# Windows adapter

This milestone establishes the Windows service lifecycle and normalized process telemetry.

## Current behavior

- Runs under the Windows Service Control Manager as `VotalNexusAgent`.
- Maintains a bootstrap process inventory with Tool Help snapshots.
- Emits newly observed process starts as the shared `SecurityEvent` JSON model.
- Attempts to resolve a full executable path with `PROCESS_QUERY_LIMITED_INFORMATION`.
- Writes JSON Lines to `C:\ProgramData\Votal\Nexus\events.jsonl`.
- Stops cleanly when the SCM sends a stop control.

## Important limitation

The snapshot loop is a bootstrap collector, **not the final EDR telemetry path**. A one-second snapshot can miss short-lived processes. The next Windows telemetry milestone replaces process polling with ETW while retaining this service lifecycle and shared event model.

No blocking is enabled in this service yet.

## Build

On Windows with Rust stable:

```powershell
cargo build --release --manifest-path platforms/windows/Cargo.toml
```

## Install for an isolated test device

Run PowerShell as Administrator after building:

```powershell
$binary = (Resolve-Path .\platforms\windows\target\release\nexus-agent-windows.exe).Path
New-Service -Name VotalNexusAgent -BinaryPathName $binary -StartupType Automatic
Start-Service VotalNexusAgent
```

Remove it with:

```powershell
Stop-Service VotalNexusAgent
sc.exe delete VotalNexusAgent
```

## Planned Windows enforcement layers

1. Replace snapshot telemetry with ETW process/image telemetry.
2. Add policy loading and Ed25519 verification through the shared core.
3. Add WFP callout/management components for network enforcement.
4. Add a signed kernel component only for controls that genuinely require kernel interception.
5. Add tamper protection, health reporting, staged enforcement, rollback, and signed installer packaging.

Keep service code and privileged driver/callout code in separate trust boundaries.
