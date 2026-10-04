# Windows installer scaffold

These PowerShell scripts install the user-mode Nexus service for isolated test and enterprise packaging work.

~~~powershell
.\platforms\windows\installer\Install-NexusAgent.ps1 -BinaryPath .\platforms\windows\target\release\nexus-agent-windows.exe
~~~

The installer copies the binary under Program Files, creates a SYSTEM/Administrators-only ProgramData state directory, registers the automatic LocalSystem service, and configures bounded restart recovery. It does not create a control-plane credential or signed policy.

Uninstall preserves state by default:

~~~powershell
.\platforms\windows\installer\Uninstall-NexusAgent.ps1
~~~

Use `-PurgeData` only when policy, event spool, health, and credentials should be removed as well.

Production distribution still needs an Authenticode-signed executable and signed MSI/MSIX or enterprise installer pipeline.
