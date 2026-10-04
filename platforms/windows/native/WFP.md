# Windows WFP controlled enforcement

This user-mode utility validates real outbound blocking through Windows Filtering Platform without introducing a custom kernel callout driver.

It installs a persistent `FWP_ACTION_BLOCK` filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` with:

- an exact remote IPv4 address condition;
- optionally an exact application identity derived from a full executable path.

The test component has a fixed filter key and replaces its previous test rule, so rollback is deterministic.

## Build

From a Visual Studio Developer Command Prompt:

```bat
cl /nologo /W4 /WX /DUNICODE /D_UNICODE ^
  platforms\windows\native\wfp_control.c ^
  /Fe:platforms\windows\native\wfp_control.exe ^
  fwpuclnt.lib ws2_32.lib rpcrt4.lib
```

## Isolated test

Run an elevated terminal on a disposable Windows VM.

Block one known test destination:

```powershell
.\wfp_control.exe install 203.0.113.10
```

Or scope the block to one existing executable:

```powershell
.\wfp_control.exe install 203.0.113.10 "C:\Path\To\test-client.exe"
```

Remove the filter immediately after validation:

```powershell
.\wfp_control.exe remove
```

Use only addresses and test applications you control. Do not begin validation with DNS servers, identity providers, endpoint management, EDR, VPN, Windows Update, or other critical destinations.

## Why no callout driver yet

WFP's built-in ALE layers can enforce simple permit/block policy directly. A custom kernel callout is only justified when Nexus needs classification logic or packet/flow inspection that built-in filter conditions cannot express. Keeping this milestone user-mode reduces crash and signing risk.
