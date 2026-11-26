<#
.SYNOPSIS
    Builds an up-to-date Windows Server template ISO from an official ISO, offline:
    verify -> scan -> service (cumulative update) -> verify build -> clean up -> re-scan -> gate
    -> bootable ISO -> SHA-256 -> manifest. No VM is started; nothing outside -WorkRoot changes.

.DESCRIPTION
    Runs as Administrator on a Windows build machine with the Windows ADK Deployment Tools
    (DISM and oscdimg of the image's Windows version or newer). The cumulative update (.msu,
    exactly as the Microsoft Update Catalog names it, with any checkpoint update beside it) is
    supplied in -UpdatesPath; the script checks it is the one MSRC says closes the open CVEs.

    Every step's evidence lands in <WorkRoot>\<BuildId>\evidence; the template ISO, SHA256SUMS
    and template-manifest.json in <WorkRoot>\<BuildId>\out. On failure the mounted image is
    discarded and the source ISO detached; the source ISO is never modified.

    Exit code 0: template built and the gate passed. Any error: non-zero, with the reason.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Build-WindowsTemplate.ps1 `
      -IsoPath E:\SSI-Image\iso\WS2025_EVAL_en-us.iso `
      -ExpectedIsoSha256 7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 `
      -ImageIndex 2 -UpdatesPath E:\SSI-Image\updates -WorkRoot E:\SSI-Image\runs
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$IsoPath,
    # Pins the source ISO; recommended. Empty: the hash is recorded but not compared.
    [string]$ExpectedIsoSha256 = '',
    # install.wim index (dism /Get-WimInfo). 2 = Standard (Desktop Experience) on Server 2025 media.
    [int]$ImageIndex = 2,
    [Parameter(Mandatory)][string]$UpdatesPath,
    [Parameter(Mandatory)][string]$WorkRoot,
    # Product name as the MSRC Security Update Guide spells it (Desktop Experience edition).
    [string]$Product = 'Windows Server 2025',
    [string]$TemplateName = 'ssi-ws2025-std-de',
    [string]$BuildId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    # Open CVEs allowed after servicing. 0: any remaining CVE fails the build.
    [int]$MaxOpenAfter = 0,
    [string]$AdkPath = (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64'),
    [int]$MinFreeGB = 60
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SsiWindowsTemplate.psm1') -Force

if ($BuildId -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'BuildId may hold letters, digits, dot, dash and underscore.' }
if ($TemplateName -notmatch '^[a-z0-9][a-z0-9-]{1,40}$') { throw 'TemplateName may hold lower-case letters, digits and dashes.' }

$run      = Join-Path $WorkRoot $BuildId
$evidence = Join-Path $run 'evidence'
$work     = Join-Path $run 'work'
$mountDir = Join-Path $run 'mount'
$scratch  = Join-Path $run 'scratch'
$isoRoot  = Join-Path $work 'iso-root'
$outDir   = Join-Path $run 'out'
$dism     = Join-Path $AdkPath 'DISM\dism.exe'
$oscdimg  = Join-Path $AdkPath 'Oscdimg\oscdimg.exe'
$hiveKey  = "SSI_TEMPLATE_$($BuildId -replace '[^A-Za-z0-9]', '_')"

function Write-Step([string]$Text) { Write-Host ''; Write-Host "==> $Text" }

# Runs a native tool; output goes to the transcript; a non-zero exit (other than the allowed
# ones) fails the build. The exit code alone decides: Windows PowerShell 5.1 turns every stderr
# line of a redirected native command into an error record, and under ErrorActionPreference=Stop
# the first one (oscdimg writes its progress to stderr) would abort the build mid-write.
function Invoke-Tool {
    param([string]$Path, [string[]]$Arguments, [int[]]$Success = @(0))
    Write-Host "$([IO.Path]::GetFileName($Path)) $($Arguments -join ' ')"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $Path @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    $output | ForEach-Object { Write-Host "  $_" }
    if ($Success -notcontains $code) { throw "$([IO.Path]::GetFileName($Path)) failed with exit code $code." }
    return , $output
}

function Get-WimImageInfo([string]$WimFile, [int]$Index) {
    $text = Invoke-Tool $dism @('/English', '/Get-WimInfo', "/WimFile:$WimFile", "/Index:$Index")
    return ConvertFrom-DismWimInfo -Text $text
}

function Get-Sha256([string]$Path) { (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

function Invoke-Scan([version]$Build, [datetime]$Since, [string]$Name) {
    $documents = @(Get-MsrcDocument -Since $Since)
    if ($documents.Count -eq 0) { throw 'MSRC returned no monthly document.' }
    $months = @($documents | ForEach-Object { [string]$_.DocumentTracking.Identification.ID.Value })
    $open = Get-OpenVulnerability -Document $documents -Product $Product -ImageBuild $Build
    $summary = Export-VulnerabilityReport -Vulnerability $open -Product $Product -ImageBuild $Build -Months $months -Path (Join-Path $evidence $Name)
    Write-Host "Open CVEs at $Build : $($summary.Total) (Critical $($summary.Critical), Important $($summary.Important), other $($summary.Other))"
    return $summary
}

$isoMounted = $false
$imageMounted = $false
$hiveLoaded = $false
New-Item -ItemType Directory -Force -Path $evidence, $work, $scratch, $outDir | Out-Null
Start-Transcript -Path (Join-Path $evidence 'build-transcript.log') | Out-Null
try {
    # 1. Preflight: administrator, tools, free space, a clean run directory.
    Write-Step 'Preflight'
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator.' }
    foreach ($tool in $dism, $oscdimg) { if (-not (Test-Path $tool)) { throw "Missing $tool. Install the Windows ADK Deployment Tools." } }
    if (Test-Path $mountDir) { throw "$mountDir already exists; use a new BuildId." }
    New-Item -ItemType Directory -Path $mountDir | Out-Null
    $drive = Get-PSDrive -Name ([IO.Path]::GetPathRoot((Resolve-Path $WorkRoot).Path).Substring(0, 1))
    $freeGB = [math]::Round($drive.Free / 1GB, 1)
    if ($freeGB -lt $MinFreeGB) { throw "Only $freeGB GB free on $($drive.Name):; at least $MinFreeGB GB needed." }
    $fileVersion = { param($path) $info = (Get-Item $path).VersionInfo; [version]('{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart) }
    $dismVersion = & $fileVersion $dism
    $tools = [ordered]@{ dism = $dismVersion.ToString(); oscdimg = (& $fileVersion $oscdimg).ToString(); powershell = $PSVersionTable.PSVersion.ToString() }
    Write-Host "DISM $($tools.dism), oscdimg $($tools.oscdimg), $freeGB GB free"

    # 2. Source ISO: hash (and pin), then attach read-only.
    Write-Step 'Source ISO'
    $isoSha256 = Get-Sha256 $IsoPath
    Write-Host "SHA-256 $isoSha256"
    if ($ExpectedIsoSha256 -and $isoSha256 -ne $ExpectedIsoSha256.ToLowerInvariant()) { throw "Source ISO SHA-256 $isoSha256 is not the pinned $ExpectedIsoSha256." }
    $volume = Mount-DiskImage -ImagePath $IsoPath -Access ReadOnly -PassThru | Get-Volume
    $isoMounted = $true
    $isoDrive = "$($volume.DriveLetter):\"
    $sourceWim = Join-Path $isoDrive 'sources\install.wim'
    if (-not (Test-Path $sourceWim)) { throw 'The ISO has no sources\install.wim.' }

    # 3. Source image and its open CVEs.
    Write-Step 'Source image'
    $source = Get-WimImageInfo $sourceWim $ImageIndex
    Write-Host "$($source.Name), build $($source.Build), created $($source.Created)"
    if ($dismVersion.Build -lt $source.Build.Build) { throw "DISM $dismVersion is older than the image (build $($source.Build.Build)); install a newer Windows ADK." }
    $since = if ($source.Created) { $source.Created.AddMonths(-1) } else { (Get-Date).AddMonths(-24) }
    $before = Invoke-Scan $source.Build $since 'scan-before'

    # 4. The update that closes them, verified against its catalog SHA-1.
    Write-Step 'Updates'
    $updates = @(Get-ChildItem -Path $UpdatesPath -Filter '*.msu' | ForEach-Object { Assert-MsuIntegrity -Path $_.FullName })
    $updates | ForEach-Object { Write-Host "$($_.Name) SHA-1 ok" }
    $target = $null
    if ($before.Total -gt 0) {
        $target = $updates | Where-Object { $_.KB -eq $before.RequiredKb } | Select-Object -First 1
        if (-not $target) { throw "MSRC says $($before.RequiredKb) (build $($before.RequiredBuild)) closes the open CVEs; put its .msu (and any checkpoint .msu listed with it) in $UpdatesPath." }
    }

    # 5. Service a single-index copy of the image.
    $wim = Join-Path $work 'install.wim'
    Write-Step "Export index $ImageIndex"
    Invoke-Tool $dism @('/English', '/Export-Image', "/SourceImageFile:$sourceWim", "/SourceIndex:$ImageIndex", "/DestinationImageFile:$wim", '/Compress:max', '/CheckIntegrity') | Out-Null

    Write-Step 'Mount'
    Invoke-Tool $dism @('/English', '/Mount-Image', "/ImageFile:$wim", '/Index:1', "/MountDir:$mountDir") | Out-Null
    $imageMounted = $true
    if ($target) {
        Write-Step "Add $($target.KB)"
        # The checkpoint update, when needed, is taken from the same folder by DISM.
        Invoke-Tool $dism @('/English', "/Image:$mountDir", '/Add-Package', "/PackagePath:$($target.Path)", "/ScratchDir:$scratch", "/LogPath:$(Join-Path $evidence 'dism-add-package.log')") -Success @(0, 3010) | Out-Null
    }

    # 6. The build the image really has now, read from its own registry.
    Write-Step 'Verify build'
    Invoke-Tool reg.exe @('load', "HKLM\$hiveKey", (Join-Path $mountDir 'Windows\System32\config\SOFTWARE')) | Out-Null
    $hiveLoaded = $true
    $currentVersion = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\$hiveKey\Microsoft\Windows NT\CurrentVersion"
    $serviced = [version]('{0}.{1}.{2}.{3}' -f $currentVersion.CurrentMajorVersionNumber, $currentVersion.CurrentMinorVersionNumber, $currentVersion.CurrentBuild, $currentVersion.UBR)
    $currentVersion = $null
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    Invoke-Tool reg.exe @('unload', "HKLM\$hiveKey") | Out-Null
    $hiveLoaded = $false
    Write-Host "Image build now $serviced"
    if ($target -and $serviced -lt [version]$before.RequiredBuild) { throw "After $($target.KB) the image is at $serviced, not $($before.RequiredBuild)." }
    Invoke-Tool $dism @('/English', "/Image:$mountDir", '/Get-Packages', '/Format:Table') | Set-Content -Path (Join-Path $evidence 'packages.txt') -Encoding UTF8

    if ($target) {
        Write-Step 'Component cleanup'
        Invoke-Tool $dism @('/English', "/Image:$mountDir", '/Cleanup-Image', '/StartComponentCleanup', '/ResetBase', "/ScratchDir:$scratch", "/LogPath:$(Join-Path $evidence 'dism-cleanup.log')") | Out-Null
    }

    Write-Step 'Commit'
    Invoke-Tool $dism @('/English', '/Unmount-Image', "/MountDir:$mountDir", '/Commit') | Out-Null
    $imageMounted = $false

    # 7. Re-scan and gate.
    Write-Step 'Re-scan'
    $after = Invoke-Scan $serviced $since 'scan-after'
    if ($after.Total -gt $MaxOpenAfter) { throw "Gate: $($after.Total) CVE(s) still open after servicing (allowed $MaxOpenAfter). See scan-after.csv." }

    # 8. Bootable ISO (BIOS + UEFI) with the serviced image as its only edition.
    Write-Step 'Template ISO'
    & robocopy.exe $isoDrive $isoRoot /E /A-:R /XF install.wim install.esd /NFL /NDL /NP /NJH | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE." }
    Invoke-Tool $dism @('/English', '/Export-Image', "/SourceImageFile:$wim", '/SourceIndex:1', "/DestinationImageFile:$(Join-Path $isoRoot 'sources\install.wim')", '/Compress:max', '/CheckIntegrity') | Out-Null
    $templateImage = Get-WimImageInfo (Join-Path $isoRoot 'sources\install.wim') 1
    if ($templateImage.Build -ne $serviced) { throw "The template image reports build $($templateImage.Build), expected $serviced." }

    $isoName = "$TemplateName-$($serviced.Build).$($serviced.Revision).iso"
    $isoOut = Join-Path $outDir $isoName
    $label = ("WS_{0}_{1}" -f $serviced.Build, $serviced.Revision)
    $bootData = '2#p0,e,b{0}#pEF,e,b{1}' -f (Join-Path $isoRoot 'boot\etfsboot.com'), (Join-Path $isoRoot 'efi\microsoft\boot\efisys.bin')
    Invoke-Tool $oscdimg @('-m', '-o', '-u2', '-udfver102', "-l$label", "-bootdata:$bootData", $isoRoot, $isoOut) | Out-Null

    # 9. Hashes and manifest.
    Write-Step 'Manifest'
    $isoSha = Get-Sha256 $isoOut
    [IO.File]::WriteAllText((Join-Path $outDir 'SHA256SUMS'), "$isoSha  $isoName`n", (New-Object Text.UTF8Encoding($false)))
    $manifest = [ordered]@{
        manifestVersion = 'ssi.os-template-manifest/v1'
        template = [ordered]@{ name = $TemplateName; version = "$($serviced.Build).$($serviced.Revision)"; os = 'windows-server-2025'; edition = $source.Name; architecture = 'amd64' }
        build    = [ordered]@{ id = $BuildId; createdAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); tools = $tools }
        base     = [ordered]@{ file = [IO.Path]::GetFileName($IsoPath); sha256 = $isoSha256; imageIndex = $ImageIndex; build = $source.Build.ToString() }
        updates  = @($updates | ForEach-Object { [ordered]@{ kb = $_.KB; file = $_.Name; sha256 = $_.Sha256; applied = ($target -and $_.Path -eq $target.Path) } })
        scan     = [ordered]@{
            source = 'Microsoft Security Update Guide (MSRC CVRF API v3.0)'
            before = [ordered]@{ build = $source.Build.ToString(); open = $before.Total; critical = $before.Critical; important = $before.Important }
            after  = [ordered]@{ build = $serviced.ToString(); open = $after.Total; critical = $after.Critical; important = $after.Important }
            gate   = [ordered]@{ maxOpenAfter = $MaxOpenAfter; passed = $true }
        }
        artifacts = @([ordered]@{ file = $isoName; format = 'iso'; sizeBytes = (Get-Item $isoOut).Length; sha256 = $isoSha; signature = $null })
        signing   = [ordered]@{ signed = $false }
    }
    [IO.File]::WriteAllText((Join-Path $outDir 'template-manifest.json'), ($manifest | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))

    Write-Host ''
    Write-Host "Template : $isoOut"
    Write-Host "SHA-256  : $isoSha"
    Write-Host "Build    : $($source.Build) -> $serviced; open CVEs $($before.Total) -> $($after.Total)"
}
finally {
    # Clean-up must run to the end even when a tool writes to stderr (see Invoke-Tool).
    $ErrorActionPreference = 'Continue'
    if ($hiveLoaded) { & reg.exe unload "HKLM\$hiveKey" 2>&1 | Out-Null }
    if ($imageMounted) {
        Write-Host 'Discarding the mounted image.'
        & $dism /English /Unmount-Image "/MountDir:$mountDir" /Discard 2>&1 | ForEach-Object { Write-Host "  $_" }
    }
    if ($isoMounted) { Dismount-DiskImage -ImagePath $IsoPath | Out-Null }
    if (Test-Path $scratch) { Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue }
    Stop-Transcript | Out-Null
}
