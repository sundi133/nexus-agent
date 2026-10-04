# Nexus Agent — Install & Test Guide

Branch: `feat/cross-platform-endpoint-core`

> Use disposable test hosts first. Start in audit/shadow mode.

## Common setup

```sh
git clone https://github.com/sundi133/nexus-agent.git
cd nexus-agent
git checkout feat/cross-platform-endpoint-core
cargo test --manifest-path core/Cargo.toml
```

Create a disposable lab signing key:

```sh
export NEXUS_POLICY_SIGNING_KEY_B64="$(openssl rand -base64 32)"
```

Sign `/tmp/nexus-policy.json`:

```sh
cargo run --manifest-path core/Cargo.toml --bin nexus-policy-sign -- \
  lab-key-1 /tmp/nexus-policy.json /tmp/policy.signed.json
```

Save the printed public key:

```sh
echo '<PUBLIC_KEY_B64>' > /tmp/policy-public-key.b64
```

Never copy the private signing key to endpoints.

---

# macOS

Requirements: macOS 13+, Xcode, Rust, XcodeGen, Apple Developer signing, approved Endpoint Security entitlement, Network Extension capability.

## Build

```sh
cargo test --manifest-path core/Cargo.toml
cargo test --manifest-path runtime/Cargo.toml
cd platforms/macos
make syntax
make package-syntax
cd Package
xcodegen generate
open NexusAgent.xcodeproj
```

Configure your Apple Developer Team for `NexusAgent`, `NexusEndpointExtension`, and `NexusFilterDataExtension`. Build and install under `/Applications/Nexus Agent.app`.

Launch the app, activate the extensions, approve them in System Settings -> Privacy & Security, then verify:

```sh
systemextensionsctl list
```

Expected:

- `ai.votal.nexus.agent.endpoint`
- `ai.votal.nexus.agent.filter-data`

## Trust root + policy

```sh
sudo mkdir -p "/Library/Application Support/Votal/NexusRuntime"
sudo cp /tmp/policy-public-key.b64 \
  "/Library/Application Support/Votal/NexusRuntime/policy-public-key.b64"

sudo mkdir -p "/Library/Application Support/Votal/Nexus"
sudo cp /tmp/policy.signed.json \
  "/Library/Application Support/Votal/Nexus/policy.signed.json"

echo 1 | sudo tee \
  "/Library/Application Support/Votal/Nexus/policy.version"
```

Health:

```sh
sudo cat "/Library/Application Support/Votal/Nexus/health.json"
```

Events:

```sh
sudo tail -f "/Library/Application Support/Votal/Nexus/events.jsonl"
```

Logs:

```sh
log stream --predicate 'subsystem == "ai.votal.nexus.agent.endpoint"' --info
```

Start with policy `mode=audit`; a test executable should run while Nexus records would-deny behavior. Then sign a higher policy version with `mode=enforce`, replace `policy.signed.json`, and advance `policy.version`.

Kill switch:

```sh
pgrep -af ai.votal.nexus.agent.endpoint
sudo kill -USR1 <PID>   # allow-all
sudo kill -USR2 <PID>   # resume enforcement
```

## Managed runtime

```sh
cargo build --release --manifest-path runtime/Cargo.toml
sudo bash platforms/macos/Deployment/install_runtime.sh \
  runtime/target/release/nexus-agent-runtime \
  /tmp/runtime.json \
  /tmp/policy-public-key.b64
sudo launchctl print system/ai.votal.nexus.runtime
```

Uninstall:

```sh
sudo bash platforms/macos/Deployment/uninstall-runtime.sh
```

Full purge:

```sh
sudo bash platforms/macos/Deployment/uninstall-runtime.sh --purge-data
```

---

# Windows

Requirements: Windows 11/Server test VM, Rust, Visual Studio Build Tools/Windows SDK, Administrator PowerShell.

## Build

```powershell
cargo test --manifest-path core/Cargo.toml
cargo test --manifest-path platforms/windows/Cargo.toml
cargo build --release --manifest-path platforms/windows/Cargo.toml
cargo build --release --manifest-path runtime/Cargo.toml
```

Agent binary: `platforms\windows\target\release\nexus-agent-windows.exe`

Runtime binary: `runtime\target\release\nexus-agent-runtime.exe`

## Install collector

```powershell
powershell -ExecutionPolicy Bypass -File .\platforms\windows\installer\Install-NexusAgent.ps1 -BinaryPath .\platforms\windows\target\release\nexus-agent-windows.exe
```

Verify:

```powershell
Get-Service VotalNexusAgent
Get-Content "C:\ProgramData\Votal\Nexus\events.jsonl" -Wait
Get-Content "C:\ProgramData\Votal\Nexus\health.json"
```

Trust root: `C:\Program Files\Votal\Nexus\policy-public-key.b64`

Signed policy: `C:\ProgramData\Votal\Nexus\policy.signed.json`

Watermark: `C:\ProgramData\Votal\Nexus\policy.version`

For the first lab validation:

```powershell
Restart-Service VotalNexusAgent
```

## WFP network test

Build:

```bat
cl /nologo /W4 /WX /DUNICODE /D_UNICODE ^
  platforms\windows\native\wfp_control.c ^
  /Fe:platforms\windows\native\wfp_control.exe ^
  fwpuclnt.lib ws2_32.lib rpcrt4.lib
```

Install one exact test destination:

```powershell
.\platforms\windows\native\wfp_control.exe install 203.0.113.10
```

Remove:

```powershell
.\platforms\windows\native\wfp_control.exe remove
```

## Install collector + runtime

```powershell
powershell -ExecutionPolicy Bypass -File .\platforms\windows\installer\Install-NexusAgent.ps1 -BinaryPath .\platforms\windows\target\release\nexus-agent-windows.exe -RuntimeBinaryPath .\runtime\target\release\nexus-agent-runtime.exe -RuntimeConfigPath C:\Temp\runtime.json -PolicyPublicKeyPath C:\Temp\policy-public-key.b64 -Force
```

Verify:

```powershell
Get-Service VotalNexusAgent
Get-Service VotalNexusRuntime
```

Install/state:

- `C:\Program Files\Votal\Nexus`
- `C:\ProgramData\Votal\Nexus`

Runtime account: `NT AUTHORITY\LocalService`.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\platforms\windows\installer\Uninstall-NexusAgent.ps1
```

Full purge:

```powershell
powershell -ExecutionPolicy Bypass -File .\platforms\windows\installer\Uninstall-NexusAgent.ps1 -PurgeData
```

---

# Linux

Recommended first test platform: Ubuntu 24.04 VM.

## Prerequisites

```sh
sudo apt update
sudo apt install -y build-essential curl nftables
```

## Build

```sh
cargo test --manifest-path core/Cargo.toml
cargo test --manifest-path platforms/linux/Cargo.toml
cargo test --manifest-path runtime/Cargo.toml
cargo build --release --manifest-path platforms/linux/Cargo.toml
cargo build --release --manifest-path runtime/Cargo.toml
```

## Install collector

```sh
sudo bash platforms/linux/scripts/install.sh \
  platforms/linux/target/release/nexus-agent-linux
```

Verify:

```sh
sudo systemctl status nexus-agent
sudo journalctl -u nexus-agent -f
sudo tail -f /var/lib/votal/nexus/events.jsonl
sudo cat /var/lib/votal/nexus/health.json
```

## Trust root + policy

```sh
sudo mkdir -p /etc/votal/nexus
sudo cp /tmp/policy-public-key.b64 /etc/votal/nexus/policy-public-key.b64
sudo cp /tmp/policy.signed.json /var/lib/votal/nexus/policy.signed.json
echo 1 | sudo tee /var/lib/votal/nexus/policy.version
sudo systemctl restart nexus-agent
```

## Shadow exec test

```sh
sudo cargo run --release --manifest-path platforms/linux/Cargo.toml --bin fanotify_shadow
```

Run `/tmp/nexus-deny-test` in another shell. It should execute while Nexus logs would-deny.

## Controlled exec blocking

Deploy a newer signed `mode=enforce` policy, then:

```sh
sudo cargo run --release --manifest-path platforms/linux/Cargo.toml --bin fanotify_enforce
```

Kill switch:

```sh
pgrep -af fanotify_enforce
sudo kill -USR1 <PID>   # allow-all
sudo kill -USR2 <PID>   # resume enforcement
```

## nftables test

```sh
sudo bash platforms/linux/scripts/nft_control.sh install 203.0.113.10
sudo nft list table inet votal_nexus
sudo bash platforms/linux/scripts/nft_control.sh remove
```

## Install collector + runtime

```sh
sudo bash platforms/linux/scripts/install.sh \
  platforms/linux/target/release/nexus-agent-linux \
  runtime/target/release/nexus-agent-runtime \
  /tmp/runtime.json \
  /tmp/policy-public-key.b64
```

Verify:

```sh
sudo systemctl status nexus-agent
sudo systemctl status nexus-runtime
```

Locations:

- `/opt/votal/nexus`
- `/etc/votal/nexus`
- `/var/lib/votal/nexus`

Collector runs privileged for fanotify. Runtime runs as `nexus-runtime`.

## Uninstall

```sh
sudo bash platforms/linux/scripts/uninstall.sh
```

Full purge:

```sh
sudo bash platforms/linux/scripts/uninstall.sh --purge-data
```

---

# MCP / AI-agent authorization

Signed policy supports `agent_action_rules` for agent ID, MCP server, tool, action kind, operation, resource prefix, and risk tags.

For strongest local attestation:

- Linux/macOS: Unix-domain socket
- Linux: kernel PID/UID/GID + executable path
- macOS: kernel peer UID/GID
- Windows: named-pipe client PID + executable path

Use per-producer credential binding for identity-specific rules.

---

# Acceptance checklist

- service survives reboot
- health file exists
- telemetry is generated
- valid signed audit policy activates
- invalid signature is rejected
- downgrade is rejected
- same policy/version is idempotent
- different content cannot reuse a version
- audit mode does not block
- narrow test target blocks in enforce mode
- kill switch restores access
- last-known-good enforcement survives bad update
- WFP/nftables rollback works
- runtime spools offline and uploads after recovery
- MCP allow / alert / deny works
- producer credential spoofing is rejected
- peer/process mismatch is rejected where supported

Recommended order: Ubuntu VM -> Windows 11 VM -> dedicated macOS test Mac -> audit -> narrow enforcement -> rollback -> runtime -> MCP -> ransomware -> pilot fleet.