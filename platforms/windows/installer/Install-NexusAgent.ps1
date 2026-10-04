[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [switch]$Force,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"
$serviceName = "VotalNexusAgent"
$installDirectory = Join-Path $env:ProgramFiles "Votal\Nexus"
$stateDirectory = Join-Path $env:ProgramData "Votal\Nexus"
$installedBinary = Join-Path $installDirectory "nexus-agent-windows.exe"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated Administrator PowerShell."
    }
}

Assert-Administrator
$sourceBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) { throw "Binary not found: $BinaryPath" }

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing -and -not $Force) {
    throw "Service $serviceName already exists. Use -Force to replace the installed binary."
}
if ($null -ne $existing -and $existing.Status -ne "Stopped") {
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
}

New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null
& icacls.exe $stateDirectory /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to harden ACLs on $stateDirectory" }
Copy-Item -LiteralPath $sourceBinary -Destination $installedBinary -Force

if ($null -eq $existing) {
    New-Service -Name $serviceName -BinaryPathName ('"{0}"' -f $installedBinary) -DisplayName "Votal Nexus Endpoint Agent" -Description "Votal Nexus endpoint telemetry and signed-policy enforcement service." -StartupType Automatic | Out-Null
} else {
    & sc.exe config $serviceName binPath= ('"{0}"' -f $installedBinary) start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to update $serviceName configuration." }
}

& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/""/0 | Out-Null
if (-not $NoStart) { Start-Service -Name $serviceName }

Write-Host "Installed $serviceName"
Write-Host "Binary: $installedBinary"
Write-Host "State:  $stateDirectory"
Write-Host "No policy or control-plane credential was created by this installer."
