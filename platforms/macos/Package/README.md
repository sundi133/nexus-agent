# macOS production packaging scaffold

This directory defines the Nexus host application plus two macOS system extensions:

- `ai.votal.nexus.agent.endpoint` — Endpoint Security
- `ai.votal.nexus.agent.filter-data` — Network Extension content filter

The project is expressed as an XcodeGen spec so the Xcode project can be regenerated rather than committing machine-generated project metadata.

## Generate

Install XcodeGen, then:

~~~sh
cd platforms/macos/Package
xcodegen generate
open NexusAgent.xcodeproj
~~~

Before signing, configure the Votal Apple Developer Team and provisioning profiles for every required capability.

## Signing capabilities

Host application:

- `com.apple.developer.system-extension.install`
- `com.apple.developer.networking.networkextension` with `content-filter-provider-systemextension`
- application group `group.ai.votal.nexus.agent`

Endpoint Security system extension:

- `com.apple.developer.endpoint-security.client`

Network filter system extension:

- `com.apple.developer.networking.networkextension` with `content-filter-provider-systemextension`
- application group `group.ai.votal.nexus.agent`

Apple must approve/provision the Endpoint Security and Network Extension capabilities for the signing team before production deployment.

## Endpoint Security behavior

The Endpoint Security system extension links the shared Rust `nexus-agent-core` static library.

At startup it reads:

`/Library/Application Support/Votal/Nexus/policy.signed.json`

The extension verifies the Ed25519 signature against the compiled public trust root, validates policy structure, applies the anti-rollback watermark, and retains the last-known-good policy. Missing or invalid policy fails open.

Synchronous authorization callbacks do not call the control plane or an LLM.

The extension currently supports:

- signed `AUTH_EXEC` decisions;
- file-behavior ransomware correlation;
- signed ransomware response policy;
- guarded terminate-process containment;
- runtime kill switch and local containment-disable switch;
- machine-readable health reporting.

## Network filter behavior

The filter data provider runs in **Network Extension system-extension mode** and starts with `NEProvider.startSystemExtensionMode()`.

The host configures `NEFilterManager` with the explicit provider bundle ID `ai.votal.nexus.agent.filter-data`. The current filter implementation supports exact-host development rules and defaults to allow when no rule matches.

The filter data provider uses the shared application group for local rule material. It must not export inspected user network content.

## Enterprise rollout

See `../Deployment/` for MDM templates covering:

- system-extension approval;
- Endpoint Security Full Disk Access / PPPC;
- Web Content Filter configuration.

Replace all signing placeholders from the final signed/notarized build before MDM import.

Production rollout still requires:

- Developer ID signing and notarization;
- Endpoint Security entitlement approval;
- Network Extension provisioning;
- MDM validation on managed Macs;
- upgrade/uninstall/rollback testing;
- false-positive and latency testing on a dedicated fleet.
