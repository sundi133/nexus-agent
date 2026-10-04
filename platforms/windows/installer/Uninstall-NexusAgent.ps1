[CmdletBinding()]
param([switch]$PurgeData)

$ErrorActionPreference = "Stop"
$serviceName = "VotalNexusAgent"
$installDirectory = Join-Path $env:ProgramFiles "Votal\Nexus"
$stateDirectory = Join-Path $env:ProgramData "Votal\Nexus"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this uninstaller from an elevated Administrator PowerShell."
    }
}

Assert-Administrator
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to delete $serviceName." }
}

if (Test-Path -LiteralPath $installDirectory) { Remove-Item -LiteralPath $installDirectory -Recurse -Force }
if ($PurgeData -and (Test-Path -LiteralPath $stateDirectory)) {
    Remove-Item -LiteralPath $stateDirectory -Recurse -Force
    Write-Host "Removed Nexus state and policy data."
} else {
    Write-Host "Preserved Nexus state at $stateDirectory."
}
Write-Host "Uninstalled $serviceName."
