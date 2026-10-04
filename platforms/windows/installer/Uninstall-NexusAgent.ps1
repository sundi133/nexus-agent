[CmdletBinding()]
param([switch]$PurgeData)

$ErrorActionPreference = "Stop"

$agentServiceName = "VotalNexusAgent"
$runtimeServiceName = "VotalNexusRuntime"
$installDirectory = Join-Path $env:ProgramFiles "Votal\Nexus"
$stateDirectory = Join-Path $env:ProgramData "Votal\Nexus"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this uninstaller from an elevated Administrator PowerShell."
    }
}

function Remove-ServiceIfPresent([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return
    }
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $Name -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to delete $Name." }
}

Assert-Administrator

# Stop runtime first so it cannot race with collector/state removal.
Remove-ServiceIfPresent $runtimeServiceName
Remove-ServiceIfPresent $agentServiceName

if (Test-Path -LiteralPath $installDirectory) {
    Remove-Item -LiteralPath $installDirectory -Recurse -Force
}

if ($PurgeData -and (Test-Path -LiteralPath $stateDirectory)) {
    Remove-Item -LiteralPath $stateDirectory -Recurse -Force
    Write-Host "Removed Nexus mutable state, policy, spool, and credentials."
} else {
    Write-Host "Preserved Nexus state at $stateDirectory."
}

Write-Host "Uninstalled $agentServiceName and $runtimeServiceName when present."
