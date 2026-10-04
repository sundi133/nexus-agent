[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [string]$RuntimeBinaryPath,
    [string]$RuntimeConfigPath,
    [string]$PolicyPublicKeyPath,
    [switch]$Force,
    [switch]$NoStart
)

$ErrorActionPreference = "Stop"

$agentServiceName = "VotalNexusAgent"
$runtimeServiceName = "VotalNexusRuntime"
$installDirectory = Join-Path $env:ProgramFiles "Votal\Nexus"
$stateDirectory = Join-Path $env:ProgramData "Votal\Nexus"
$installedAgentBinary = Join-Path $installDirectory "nexus-agent-windows.exe"
$installedRuntimeBinary = Join-Path $installDirectory "nexus-agent-runtime.exe"
$installedRuntimeConfig = Join-Path $installDirectory "runtime.json"
$installedPolicyPublicKey = Join-Path $installDirectory "policy-public-key.b64"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated Administrator PowerShell."
    }
}

function Stop-ServiceIfPresent([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne "Stopped") {
        Stop-Service -Name $Name -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    return $service
}

function Assert-File([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label path is required."
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label not found: $Path"
    }
    return $resolved
}

Assert-Administrator

$sourceAgent = Assert-File $BinaryPath "Agent binary"

$runtimeArgs = @($RuntimeBinaryPath, $RuntimeConfigPath, $PolicyPublicKeyPath)
$runtimeProvided = ($runtimeArgs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
if ($runtimeProvided -ne 0 -and $runtimeProvided -ne 3) {
    throw "RuntimeBinaryPath, RuntimeConfigPath, and PolicyPublicKeyPath must be provided together."
}
$installRuntime = ($runtimeProvided -eq 3)

if ($installRuntime) {
    $sourceRuntime = Assert-File $RuntimeBinaryPath "Runtime binary"
    $sourceRuntimeConfig = Assert-File $RuntimeConfigPath "Runtime config"
    $sourcePolicyPublicKey = Assert-File $PolicyPublicKeyPath "Policy public key"
}

$existingAgent = Get-Service -Name $agentServiceName -ErrorAction SilentlyContinue
$existingRuntime = Get-Service -Name $runtimeServiceName -ErrorAction SilentlyContinue

if (-not $Force) {
    if ($null -ne $existingAgent) {
        throw "Service $agentServiceName already exists. Use -Force to replace it."
    }
    if ($installRuntime -and $null -ne $existingRuntime) {
        throw "Service $runtimeServiceName already exists. Use -Force to replace it."
    }
}

Stop-ServiceIfPresent $runtimeServiceName | Out-Null
Stop-ServiceIfPresent $agentServiceName | Out-Null

New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $stateDirectory | Out-Null

$aclArgs = @(
    $stateDirectory,
    "/inheritance:r",
    "/grant:r",
    "*S-1-5-18:(OI)(CI)F",
    "*S-1-5-32-544:(OI)(CI)F"
)
if ($installRuntime) {
    $aclArgs += "*S-1-5-19:(OI)(CI)M"
}
& icacls.exe @aclArgs | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to harden ACLs on $stateDirectory" }

Copy-Item -LiteralPath $sourceAgent -Destination $installedAgentBinary -Force

if ($installRuntime) {
    Copy-Item -LiteralPath $sourceRuntime -Destination $installedRuntimeBinary -Force
    Copy-Item -LiteralPath $sourcePolicyPublicKey -Destination $installedPolicyPublicKey -Force

    $runtimeConfig = Get-Content -LiteralPath $sourceRuntimeConfig -Raw | ConvertFrom-Json
    $runtimeConfig.spool_dir = (Join-Path $stateDirectory "spool")
    $runtimeConfig.policy_signed_path = (Join-Path $stateDirectory "policy.signed.json")
    $runtimeConfig.policy_watermark_path = (Join-Path $stateDirectory "policy.version")
    $runtimeConfig.policy_public_key_file = $installedPolicyPublicKey
    $runtimeConfig.event_source_path = (Join-Path $stateDirectory "events.jsonl")
    $runtimeConfig.event_offset_path = (Join-Path $stateDirectory "events.offset")
    $runtimeConfig.health_source_path = (Join-Path $stateDirectory "health.json")
    $runtimeConfig | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $installedRuntimeConfig -Encoding UTF8
}

if ($null -eq $existingAgent) {
    $agentParams = @{
        Name = $agentServiceName
        BinaryPathName = ('"{0}"' -f $installedAgentBinary)
        DisplayName = "Votal Nexus Endpoint Agent"
        Description = "Votal Nexus endpoint telemetry and signed-policy enforcement service."
        StartupType = "Automatic"
    }
    New-Service @agentParams | Out-Null
} else {
    & sc.exe config $agentServiceName binPath= ('"{0}"' -f $installedAgentBinary) start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to update $agentServiceName configuration." }
}

& sc.exe failure $agentServiceName reset= 86400 actions= restart/5000/restart/15000/""/0 | Out-Null

if ($installRuntime) {
    if ($null -eq $existingRuntime) {
        & sc.exe create $runtimeServiceName binPath= ('"{0}"' -f $installedRuntimeBinary) start= auto obj= "NT AUTHORITY\LocalService" DisplayName= "Votal Nexus Managed Runtime" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to create $runtimeServiceName." }
    } else {
        & sc.exe config $runtimeServiceName binPath= ('"{0}"' -f $installedRuntimeBinary) start= auto obj= "NT AUTHORITY\LocalService" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to update $runtimeServiceName configuration." }
    }

    & sc.exe description $runtimeServiceName "Votal Nexus control-plane policy, health, and telemetry runtime." | Out-Null
    & sc.exe failure $runtimeServiceName reset= 86400 actions= restart/10000/restart/30000/""/0 | Out-Null
}

if (-not $NoStart) {
    Start-Service -Name $agentServiceName
    if ($installRuntime) {
        Start-Service -Name $runtimeServiceName
    }
}

Write-Host "Installed $agentServiceName"
Write-Host "Agent binary: $installedAgentBinary"
Write-Host "Mutable state: $stateDirectory"

if ($installRuntime) {
    Write-Host "Installed $runtimeServiceName as LocalService"
    Write-Host "Runtime binary: $installedRuntimeBinary"
    Write-Host "Runtime config: $installedRuntimeConfig"
    Write-Host "Policy trust root: $installedPolicyPublicKey"
    Write-Host "Provision the bearer-token file referenced by runtime.json before expecting control-plane connectivity."
} else {
    Write-Host "Managed runtime sidecar was not installed."
}

Write-Host "No signed policy or control-plane credential was created by this installer."
