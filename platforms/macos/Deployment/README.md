# macOS enterprise deployment templates

These profiles are templates. Replace all `REPLACE_WITH_*` values from the final signed/notarized build before importing them into an MDM.

The deployment uses two system extensions:

- `ai.votal.nexus.agent.endpoint` — Endpoint Security
- `ai.votal.nexus.agent.filter-data` — Network Extension content filter

## Required replacements

1. Replace `REPLACE_WITH_TEAM_ID` with the Apple Developer Team ID used to sign the app and both system extensions.
2. Replace `REPLACE_WITH_ENDPOINT_DESIGNATED_REQUIREMENT` with the designated requirement from the signed Endpoint Security system extension.
3. Replace `REPLACE_WITH_FILTER_DESIGNATED_REQUIREMENT` with the designated requirement from the signed network filter system extension.

After building the final app, inspect requirements with commands like:

~~~sh
codesign -dv --verbose=4 "/Applications/Nexus Agent.app"
codesign -dr - "/Applications/Nexus Agent.app/Contents/Library/SystemExtensions/ai.votal.nexus.agent.endpoint.systemextension"
codesign -dr - "/Applications/Nexus Agent.app/Contents/Library/SystemExtensions/ai.votal.nexus.agent.filter-data.systemextension"
~~~

Use the requirement expression after `designated =>` as the profile value.

## Profiles

- `SystemExtensions.mobileconfig.template`: approves both system extensions and disables user approval of unrelated extensions.
- `PPPC-FullDiskAccess.mobileconfig.template`: grants SystemPolicyAllFiles / Full Disk Access to the Endpoint Security extension.
- `WebContentFilter.mobileconfig.template`: enables the Nexus filter data provider for socket filtering.

Deploy these through the macOS device channel using your MDM. Keep the app signed/notarized and install it under `/Applications` before activation testing.

Do not ship the template placeholders as production profiles.
