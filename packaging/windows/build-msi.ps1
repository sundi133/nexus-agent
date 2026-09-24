# Build VotalAgent.msi (requires the WiX v4+ dotnet tool:
#   dotnet tool install --global wix
#   wix extension add -g WixToolset.Util.wixext)
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$Arch = "amd64",
  [string]$CertThumbprint = ""
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$bin = "$root\dist\votal-agent_windows_$Arch.exe"
$wixArch = @{ amd64 = "x64"; arm64 = "arm64" }[$Arch]
$out = "$root\dist\VotalAgent-$Version-$wixArch.msi"

if ($CertThumbprint) {
  signtool sign /sha1 $CertThumbprint /fd sha256 /tr http://timestamp.digicert.com /td sha256 $bin
}
wix build "$PSScriptRoot\VotalAgent.wxs" -ext WixToolset.Util.wixext `
  -d Version=$Version -d BinPath=$bin -arch $wixArch -o $out
if ($CertThumbprint) {
  signtool sign /sha1 $CertThumbprint /fd sha256 /tr http://timestamp.digicert.com /td sha256 $out
}
Write-Host "built $out"
