# Votal Agent

A cross-platform endpoint agent for **Votal**. It reports device posture, finds AI agents and the MCP servers wired into them, and enforces AI access policy on the device.

One Go codebase builds native binaries for **macOS, Windows and Linux**. About 90% of the logic is shared; only small OS modules differ.

```text
                 Votal Cloud  (policies, RBAC, device groups, risk, audit, dashboards)
                      │  HTTPS / JSON
                 Votal Agent  (this repo: "dumb and reliable")
                      │
        ┌─────────────┼──────────────┬───────────────┐
        ▼             ▼              ▼               ▼
     osquery      OS modules     AI detector    Policy engine ◀── local decision API
   (inventory)  darwin/windows/  (agents, MCP    (evaluates the      (MCP gateway,
                   linux          servers, graph)  cached bundle)     IDE plugins)
```

## Layout

```text
cmd/
  votal-agent/        agent binary (run, enroll, configure, collect, detect, decide)
  votal-devserver/    in-memory fake of the Votal cloud API for local dev
internal/
  agent/              core: enrollment, heartbeat, telemetry, policy sync, commands, updater
  api/                wire protocol + HTTP client (agent ⇄ cloud)
  config/             JSON config + env overrides
  platform/           Platform interface
    darwin.go         macOS: ps, lsof, plutil/Info.plist, FileVault, SIP, Gatekeeper
    windows.go        Windows: Toolhelp32, registry, WTS, BitLocker, Defender, UAC
    linux.go          Linux: /proc, dpkg/rpm/pacman, dm-crypt, ufw/firewalld, SELinux/AppArmor
    parse.go          OS-tool output parsers (untagged → unit-tested on every OS)
  osquery/            read-only osquery runner (SELECT-only guard)
  detector/           AI agent registry (embedded JSON), MCP config parsing, redaction, graph
  policy/             policy engine + persisted bundle store
  telemetry/          collector (platform + osquery + detector → events), bounded buffer
  localapi/           loopback policy decision API
  service/            launchd / systemd / Windows SCM integration
  secure/             state/config dir lockdown (0700 / SYSTEM+Admins DACL)
packaging/
  macos/              LaunchDaemon plist, pkg scripts, build-pkg.sh (sign + notarize)
  windows/            WiX v4 MSI (service install, recovery actions, silent-install props)
  linux/              hardened systemd unit, nfpm config for .deb/.rpm
scripts/              cross-compile, update signing
examples/             dev config, sample policy bundle
```

## Quick start (no cloud needed)

```bash
go build -o bin/votal-agent ./cmd/votal-agent

bin/votal-agent collect     # full telemetry snapshot of this machine
bin/votal-agent detect      # AI agents, MCP servers, agent → MCP → resource graph
bin/votal-agent decide -policy examples/policy.json \
    -user alice -agent cursor -resource production_database -action write   # exit 4 = deny
```

## End-to-end with the dev cloud

```bash
make dev-server     # terminal 1: fake Votal cloud on 127.0.0.1:8080
make dev-agent      # terminal 2: agent enrolls, syncs policy, ships telemetry

# Ask the on-device policy decision point (what an MCP gateway would do):
curl -s -X POST localhost:7443/v1/decide -H 'Content-Type: application/json' \
  -d '{"user":"alice","agent_id":"cursor","resource":"production_database","action":"write"}'
# → {"decision":"deny","policy_id":"pol_prod_db",...}

# Send the device a command from the "cloud":
DEV=$(curl -s localhost:8080/admin/devices | jq -r '.[0].id')
curl -s -X POST localhost:8080/admin/devices/$DEV/commands -d '{"type":"collect_telemetry"}'
curl -s localhost:8080/admin/results
```

## How it works

### Agent lifecycle
1. **Enroll**: the agent sends an org enrollment token, device info and a *hashed* hardware ID. It gets back `device_id` and a per-device `agent_token`, which it stores in `identity.json` (0600, or a SYSTEM/Admins-only DACL on Windows). If the cloud rejects the token 3 times in a row (it was revoked or rotated), the agent re-enrolls.
2. **Loops**. Each loop adds ±10% jitter and backs off on errors:

   | loop      | default | what it does |
   |-----------|---------|--------------|
   | heartbeat | 60s     | liveness; the cloud can nudge a policy refresh or command poll |
   | policy    | 5m      | ETag-aware bundle fetch; validated before activation; cached on disk |
   | telemetry | 15m     | full snapshot → bounded buffer (5k events, drop-oldest) → batched upload |
   | commands  | 30s     | fixed allow-list, at-most-once execution, expiry honoured |
   | updates   | 6h      | signed self-update (see below) |

3. **Local decision API** (`127.0.0.1:7443`) starts *before* enrollment, so the cached policy keeps protecting the device while the cloud is unreachable.

### Telemetry events
`device_info`, `security_posture`, `process_inventory`, `network_connections`, `application_inventory`, `ai_agent_inventory`, `ai_agent_graph`, `policy_decision`, `osquery_result`.

Application inventory comes from osquery when it's installed, and from the native OS module otherwise. Posture checks use shared IDs on every OS (`disk_encryption`, `firewall`, `antivirus`, `os_protection`, `app_control`), so the cloud can compare fleets directly.

### AI agent detection
`internal/detector/registry.json` is data, not code. Add a product without touching Go:

| signal | example |
|---|---|
| process name (case-sensitive; `.exe` stripped) | `Cursor`, `claude`, `ollama` |
| installed app / bundle ID | `com.todesktop.230313mzl4w4u92` |
| listening port **owned by** a known process | Ollama on 11434 |
| editor extensions | `~/.vscode/extensions/github.copilot-*` |
| MCP config files in **every** user's home | `{config}/Claude/claude_desktop_config.json`, `~/.cursor/mcp.json`, `~/.claude.json` (incl. per-project), `~/.codex/config.toml`, VS Code `mcp.json`, Windsurf, Gemini CLI |

Each MCP server is classified into resource hints (`github`, `database:postgres`, `kubernetes`, `filesystem`, `browser`…) and turned into graph edges:

```text
device:dev_1 ──runs──▶ agent:cursor ──uses_mcp──▶ mcp:prod-db ──accesses──▶ resource:database:postgres
```

**Secrets never leave the device.** Only env var and header *names* are sent, never their values. Credential-looking args (`--api-key X`, `--token=…`, `ghp_…`, `sk-…`, JWTs, AWS keys) are redacted, and so are URL passwords and secret query params.

### Policy engine
Bundles are authored in the cloud; the agent only evaluates them. The YAML policy from the design translates directly to the bundle JSON (see `examples/policy.json`):

```json
{
  "id": "pol_prod_db", "name": "Production Database Protection", "mode": "enforce",
  "conditions": {"device": {"managed": true}, "user": {"group": "engineering"}, "agent": {"type": "ai_agent"}},
  "resources": ["production_database", "db:prod/*"],
  "actions": ["read"],
  "deny": ["write", "delete", "export"]
}
```

Evaluation rules:
- An `enforce` deny always wins.
- Otherwise an explicit allow applies.
- Otherwise the bundle's `default_decision` applies.
- With **no bundle at all, the answer is deny** (fail closed).

`monitor` mode reports `monitor_deny: true` but never blocks, so a new policy can be trialled before it's enforced. `agent.type: "ai_agent"` matches any AI category. In patterns, `*` matches any characters, including `/`.

User groups come from the bundle's `directory` (synced from the IdP by the cloud), **never from the caller**. Otherwise any local process could claim to be in `admins`.

Every decision is logged as a `policy_decision` event for the audit trail.

### Security model
- TLS 1.2+ with optional CA pinning (`ca_file`). `http://` is refused unless `allow_insecure_http` is set (dev only).
- There is no remote shell. Commands are a fixed allow-list: `collect_telemetry`, `refresh_policy`, `osquery_query` (single read-only SELECT), `check_update`, `lock_screen`, `notify_user`.
- The local API binds loopback only. It rejects requests that carry `Origin` or `Sec-Fetch-*` headers or a non-loopback `Host` (blocks browser CSRF and DNS rebinding), requires `application/json`, and rejects unknown fields.
- Self-update installs a binary only if its SHA-256 is signed with the **pinned** ed25519 key (`update_public_key`). It refuses downgrades and non-HTTPS URLs, and keeps `.old` for rollback. With no key configured, self-update is off and MDM or the package manager handles upgrades. Keys come from `go run scripts/sign-update.go keygen`.
- Command lines are never collected; they often contain credentials.

## Building and packaging

```bash
make test                 # unit tests (race detector)
make lint                 # gofmt + go vet for linux, darwin AND windows
VERSION=0.1.0 make dist   # dist/votal-agent_{darwin,linux,windows}_{amd64,arm64}
```

| OS | Package | Install location | Service |
|---|---|---|---|
| macOS | `packaging/macos/build-pkg.sh` → `VotalAgent.pkg` (universal, signed + notarized) | `/Library/Votal/votal-agent` | LaunchDaemon `com.votal.agent` |
| Windows | `packaging/windows/build-msi.ps1` → `VotalAgent.msi` | `C:\Program Files\Votal\` | Service `VotalAgent` (LocalSystem, auto-restart) |
| Linux | `nfpm` with `packaging/linux/nfpm.yaml` → `.deb` / `.rpm` | `/usr/bin/votal-agent` | systemd `votal-agent.service` (hardened) |

Mass deployment:
- **Windows** (Intune/SCCM/GPO): `msiexec /i VotalAgent.msi /qn SERVER_URL=https://api.votal.ai ENROLLMENT_TOKEN=…`
- **macOS** (Jamf/Kandji/Intune): drop `/Library/Votal/install.env` before installing the pkg.
- **Linux**: set `VOTAL_SERVER_URL` / `VOTAL_ENROLLMENT_TOKEN` in the environment of the package install.

All three call `votal-agent configure`, which writes the config with locked-down permissions.

## Roadmap
- **Cloud side**: the real API behind `internal/api` (the dev server shows the contract), per-device policy compilation, risk scoring.
- **MCP gateway**: a stdio/HTTP MCP proxy that calls `/v1/decide` per tool call. The agent can rewrite detected MCP configs to route through it.
- **Registry updates** pushed from the cloud, so new AI tools are detected without a new agent release.
- **Deeper OS signals**: Endpoint Security framework (macOS) and ETW (Windows) for real-time process and network events instead of polling.
- **Mobile** through MDM integrations, not a desktop-agent port.
