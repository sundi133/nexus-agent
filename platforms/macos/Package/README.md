# macOS production packaging scaffold

This directory defines the host application and Endpoint Security system extension packaging boundary.

The project is expressed as an XcodeGen spec so the Xcode project can be regenerated rather than committing fragile machine-generated project metadata.

## Generate

Install XcodeGen, then:

```sh
cd platforms/macos/Package
xcodegen generate
open NexusAgent.xcodeproj
```

Before signing, replace automatic/team settings with the Votal Apple Developer team and provisioning profiles that contain the required managed capabilities.

## Signing capabilities

Host application:

- `com.apple.developer.system-extension.install`

Endpoint Security extension:

- `com.apple.developer.endpoint-security.client`

Apple must approve the Endpoint Security entitlement for the development team before deployment.

## Current safety mode

The packaged system extension subscribes to `AUTH_EXEC` but always responds `ALLOW`. This is intentional. The separate development enforcement harness proves the deny/kill-switch path while this target establishes the signed installation lifecycle.

The system extension now links the Rust `nexus-agent-core` static library. At startup it reads `/Library/Application Support/Votal/Nexus/policy.signed.json`, verifies the Ed25519 signature against the public trust root compiled into `NexusTrustRoot.h`, and loads the policy only if verification succeeds. Any missing/invalid policy or unconfigured trust root leaves the extension fail-open.

`scripts/build_core_universal.sh` builds arm64 and x86_64 Rust static libraries and combines them for Xcode. The private policy-signing key must remain in the control-plane signing environment; only the public key belongs in the endpoint binary.

Before production, add authenticated policy rotation/reload and replace the zeroed development trust root.

## Enterprise rollout

Production deployment also requires the appropriate MDM system-extension approval and Full Disk Access/privacy configuration for managed Macs. Keep audit/allow-only mode until extension activation, health, policy verification, and rollback have been tested on a dedicated fleet.
