# Enterprise deployment runbook

This runbook defines the intended order for staging Nexus Agent. It is not a substitute for platform signing, notarization, MDM, or package-management policy.

## 1. Build and sign

- macOS: build the host app plus Endpoint Security and Network Extension system extensions; sign all products with the same approved Developer ID team and notarize the final app.
- Windows: build the Rust service and WFP component, Authenticode-sign the executable/installer, and distribute through the enterprise software-management channel.
- Linux: build for each supported distro/architecture and package/sign native DEB/RPM artifacts for production.

The private Ed25519 policy-signing key stays in the control-plane signing environment. Endpoints contain only the public verification key.

## 2. Provision platform permissions

### macOS

Use the templates in `platforms/macos/Deployment/` after replacing the Team ID and designated-requirement placeholders from the final signed build.

Deployment order:

1. System Extension approval profile.
2. Endpoint Security Full Disk Access/privacy profile.
3. Web Content Filter profile.
4. Signed/notarized `Nexus Agent.app` under `/Applications`.
5. Activate both system extensions and verify health before enabling signed enforcement policy.

The legacy PPPC template supports the project’s macOS 13+ baseline. Apple deprecates the legacy PPPC identity payload in macOS 27; macOS 27 fleet work should evaluate the current declarative app-settings privacy configuration before rollout.

### Windows

Use `platforms/windows/installer/Install-NexusAgent.ps1` from an elevated deployment context after code signing. The installer creates the service and hardens the ProgramData state directory, but intentionally does not create a credential or policy.

### Linux

Use native signed DEB/RPM packages for production. `platforms/linux/scripts/install.sh` is a staging scaffold that installs the binary/systemd unit and creates a root-only state directory.

## 3. Enroll / configure runtime

Provision the control-plane URL and endpoint credential through the enterprise secret/configuration channel. Do not bake bearer tokens into installers, source code, GitHub Actions variables that are exposed to pull requests, or public MDM profiles.

Install only Ed25519-signed policy bundles. Policy anti-rollback prevents a lower policy version from replacing the active last-known-good version.

Start with:

1. telemetry-only;
2. signed policy in audit/shadow mode;
3. narrow network/process enforcement on a dedicated test fleet;
4. ransomware response in shadow mode;
5. terminate-process response only after false-positive and rollback validation.

## 4. Health gates

Do not call an endpoint protected solely because the service is installed. Require machine-readable capability health:

- verified policy version present;
- native telemetry source active (not fallback/unavailable unless explicitly accepted);
- network enforcement state matches intended rollout;
- ransomware detection state matches intended rollout;
- ransomware response state is disabled/shadow/active as intended;
- no unexpected kill/containment switch is engaged;
- control-plane check-in and event spool are healthy.

## 5. Rollback

- Policy rollback: publish a new **higher-version** signed policy that disables enforcement; do not try to replay an older policy version.
- Ransomware containment: use the platform local containment-disable switch while diagnosing false positives.
- macOS AUTH_EXEC: the existing runtime kill switch forces allow behavior.
- Windows WFP and Linux nftables components own isolated rules/session state so their test enforcement can be removed without changing unrelated firewall policy.
- Uninstallers preserve state by default for forensics/reinstall; purge only when explicitly required.

## 6. Production validation still required

- real entitled macOS devices under the target MDM;
- Windows VM/physical workload and upgrade testing;
- supported Linux distro/kernel matrix;
- signing/notarization/package verification;
- install/upgrade/uninstall/rollback soak tests;
- latency, dropped-event, CPU, memory, disk-spool, and false-positive targets;
- tamper and least-privilege review.
