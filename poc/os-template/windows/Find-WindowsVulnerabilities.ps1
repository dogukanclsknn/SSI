<#
.SYNOPSIS
    Lists the CVEs still open in an offline Windows image (Microsoft MSRC data). Read-only.

.DESCRIPTION
    Every CVE whose vendor fix for -Product ships in a build newer than -ImageBuild is open in
    the image. Writes <OutPrefix>.csv (one row per CVE) and <OutPrefix>.json (summary, including
    the cumulative update that closes them all).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Find-WindowsVulnerabilities.ps1 `
      -ImageBuild 10.0.26100.32230 -Since 2026-01-01 -OutPrefix E:\SSI-Image\evidence\scan-before
#>
[CmdletBinding()]
param(
    [string]$Product = 'Windows Server 2025',
    [Parameter(Mandatory)][version]$ImageBuild,
    # Oldest MSRC month to read; the month the image was built in is enough.
    [Parameter(Mandatory)][datetime]$Since,
    [Parameter(Mandatory)][string]$OutPrefix
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SsiWindowsTemplate.psm1') -Force

$documents = @(Get-MsrcDocument -Since $Since)
if ($documents.Count -eq 0) { throw "MSRC returned no monthly document released since $($Since.ToString('yyyy-MM-dd'))." }
$months = @($documents | ForEach-Object { [string]$_.DocumentTracking.Identification.ID.Value })
$open = Get-OpenVulnerability -Document $documents -Product $Product -ImageBuild $ImageBuild
$summary = Export-VulnerabilityReport -Vulnerability $open -Product $Product -ImageBuild $ImageBuild -Months $months -Path $OutPrefix

Write-Host "Product        : $Product"
Write-Host "Image build    : $ImageBuild"
Write-Host "MSRC months    : $($months -join ', ')"
Write-Host "Open CVEs      : $($summary.Total) (Critical $($summary.Critical), Important $($summary.Important), other $($summary.Other))"
if ($summary.Total -gt 0) {
    Write-Host "Closed by      : $($summary.RequiredKb) (build $($summary.RequiredBuild)) - cumulative"
} else {
    Write-Host 'Closed by      : nothing to install; the image is current.'
}
Write-Host "Report         : $OutPrefix.csv, $OutPrefix.json"
