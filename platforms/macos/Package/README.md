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

The next packaging step is to link the Rust `nexus-agent-core` static library into the system extension, load an Ed25519-signed policy snapshot at startup, and only then enable narrow enforcement.

## Enterprise rollout

Production deployment also requires the appropriate MDM system-extension approval and Full Disk Access/privacy configuration for managed Macs. Keep audit/allow-only mode until extension activation, health, policy verification, and rollback have been tested on a dedicated fleet.
