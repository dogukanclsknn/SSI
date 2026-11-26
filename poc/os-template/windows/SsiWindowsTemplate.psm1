# SSI - Windows OS template: shared functions (docs/os-template-poc.md, "Windows").
#
# Vulnerability detection for an offline Windows image: Trivy does not scan Windows, so the
# image's build (Version + ServicePack Build, e.g. 10.0.26100.32230) is compared with Microsoft's
# Security Update Guide data (MSRC CVRF API v3.0). Every CVE whose vendor fix for the product
# ships in a build newer than the image's build is still open in the image.
#
# Pure functions (no I/O) are kept apart from the MSRC download so they can be tested with
# fixtures. Windows PowerShell 5.1 compatible: no PowerShell 7-only syntax.

Set-StrictMode -Version 1.0   # CVRF documents omit optional fields; property access must stay lenient

$script:MsrcApi = 'https://api.msrc.microsoft.com/cvrf/v3.0'
$script:SeverityOrder = @{ 'Critical' = 0; 'Important' = 1; 'Moderate' = 2; 'Low' = 3 }

# CVRF enumerations used here (Microsoft CVRF schema): Remediation Type 2 = Vendor Fix,
# Threat Type 3 = Severity.
$script:VendorFix = 2
$script:SeverityThreat = 3

function ConvertTo-BuildVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $parsed = $null
    if ([version]::TryParse($Value.Trim(), [ref]$parsed)) { return $parsed }
    return $null
}

function Test-ProductMatch {
    param($ProductIds, [string[]]$Wanted)
    foreach ($id in @($ProductIds)) { if ($Wanted -contains [string]$id) { return $true } }
    return $false
}

# CVRF documents -> the CVEs still open in an image of $Product at $ImageBuild. When a CVE has
# several fixes (re-releases, hotpatch and full builds) the newest build is the one that closes it.
function Get-OpenVulnerability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Document,
        [Parameter(Mandatory)][string]$Product,
        [Parameter(Mandatory)][version]$ImageBuild
    )
    $found = @{}
    foreach ($doc in $Document) {
        $productIds = @($doc.ProductTree.FullProductName |
            Where-Object { $_.Value -eq $Product } | ForEach-Object { [string]$_.ProductID })
        if ($productIds.Count -eq 0) { continue }

        foreach ($vulnerability in @($doc.Vulnerability)) {
            foreach ($fix in @($vulnerability.Remediations)) {
                if ($null -eq $fix -or [int]$fix.Type -ne $script:VendorFix) { continue }
                if (-not ($fix.PSObject.Properties.Name -contains 'FixedBuild') -or -not $fix.FixedBuild) { continue }
                if (-not (Test-ProductMatch $fix.ProductID $productIds)) { continue }
                $fixedBuild = ConvertTo-BuildVersion $fix.FixedBuild
                if ($null -eq $fixedBuild -or $fixedBuild -le $ImageBuild) { continue }

                $severity = $null
                foreach ($threat in @($vulnerability.Threats)) {
                    if ($null -ne $threat -and [int]$threat.Type -eq $script:SeverityThreat -and
                        (Test-ProductMatch $threat.ProductID $productIds)) {
                        $severity = [string]$threat.Description.Value; break
                    }
                }
                $score = $null
                foreach ($set in @($vulnerability.CVSSScoreSets)) {
                    if ($null -ne $set -and (Test-ProductMatch $set.ProductID $productIds)) {
                        $score = [double]$set.BaseScore; break
                    }
                }

                $cve = [string]$vulnerability.CVE
                $previous = $found[$cve]
                if ($null -eq $previous -or $previous.FixedBuildVersion -lt $fixedBuild) {
                    $found[$cve] = [pscustomobject]@{
                        CVE               = $cve
                        Title             = [string]$vulnerability.Title.Value
                        Severity          = $severity
                        CVSS              = $score
                        KB                = 'KB' + [string]$fix.Description.Value
                        FixedBuild        = [string]$fix.FixedBuild
                        FixedBuildVersion = $fixedBuild
                        Month             = [string]$doc.DocumentTracking.Identification.ID.Value
                    }
                }
            }
        }
    }
    $rank = { $order = $script:SeverityOrder[[string]$_.Severity]; if ($null -eq $order) { 9 } else { $order } }
    return @($found.Values | Sort-Object -Property @{ Expression = $rank }, CVE)
}

# Counts and the update that closes everything: the fix with the newest build. Windows cumulative
# updates contain every earlier fix, so that one update closes all open CVEs.
function Get-VulnerabilitySummary {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Vulnerability = @())
    # An empty result reaches here as $null; never count it as a row.
    $rows = @($Vulnerability | Where-Object { $null -ne $_ })
    $latest = $rows | Sort-Object -Property FixedBuildVersion -Descending | Select-Object -First 1
    $count = { param($name) @($rows | Where-Object { $_.Severity -eq $name }).Count }
    return [pscustomobject]@{
        Total         = $rows.Count
        Critical      = & $count 'Critical'
        Important     = & $count 'Important'
        Other         = @($rows | Where-Object { $_.Severity -ne 'Critical' -and $_.Severity -ne 'Important' }).Count
        RequiredKb    = if ($latest) { $latest.KB } else { $null }
        RequiredBuild = if ($latest) { $latest.FixedBuild } else { $null }
    }
}

# Microsoft Update Catalog names an .msu file <name>-kb<number>-<arch>_<sha1>.msu.
function Get-MsuInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $name = [System.IO.Path]::GetFileName($Path)
    $kb = $null; $sha1 = $null
    if ($name -match '(?i)-kb(\d+)-') { $kb = 'KB' + $Matches[1] }
    if ($name -match '(?i)_([0-9a-f]{40})\.msu$') { $sha1 = $Matches[1].ToLowerInvariant() }
    return [pscustomobject]@{ Path = $Path; Name = $name; KB = $kb; Sha1FromName = $sha1 }
}

# Verifies an .msu against the SHA-1 in its catalog file name; refuses a file without one.
function Assert-MsuIntegrity {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $info = Get-MsuInfo -Path $Path
    if (-not $info.Sha1FromName) {
        throw "$($info.Name): the file name carries no SHA-1; use the file exactly as the Microsoft Update Catalog names it."
    }
    $actual = (Get-FileHash -Path $Path -Algorithm SHA1).Hash.ToLowerInvariant()
    if ($actual -ne $info.Sha1FromName) {
        throw "$($info.Name): SHA-1 $actual does not match the catalog name; the file is damaged or not the original."
    }
    $info | Add-Member -NotePropertyName Sha256 -NotePropertyValue (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return $info
}

# `dism /English /Get-WimInfo /Index:N` text -> name, build, creation time.
function ConvertFrom-DismWimInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Text)
    $values = @{}
    foreach ($line in $Text) {
        if ($line -match '^\s*([A-Za-z ]+?)\s*:\s*(.*)$') { $values[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    foreach ($key in 'Name', 'Version', 'ServicePack Build') {
        if (-not $values.ContainsKey($key)) { throw "DISM output has no '$key' line." }
    }
    $created = $null
    if ($values.ContainsKey('Created')) {
        $parsed = [datetime]::MinValue
        $stamp = $values['Created'] -replace '\s+-\s+', ' '
        if ([datetime]::TryParse($stamp, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsed)) { $created = $parsed }
    }
    return [pscustomobject]@{
        Name    = $values['Name']
        Edition = $values['Edition']
        Build   = [version]("{0}.{1}" -f $values['Version'], $values['ServicePack Build'])
        Created = $created
    }
}

# MSRC monthly CVRF documents released on or after $Since (network).
function Get-MsrcDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory)][datetime]$Since)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $headers = @{ Accept = 'application/json' }
    $updates = (Invoke-RestMethod -Uri "$script:MsrcApi/updates" -Headers $headers -UseBasicParsing).value |
        Where-Object { [datetime]$_.InitialReleaseDate -ge $Since } | Sort-Object { [datetime]$_.InitialReleaseDate }
    foreach ($update in $updates) {
        Write-Verbose "MSRC $($update.ID)"
        Invoke-RestMethod -Uri "$script:MsrcApi/cvrf/$($update.ID)" -Headers $headers -UseBasicParsing
    }
}

# Writes the vulnerability list (CSV) and summary (JSON) of one scan; returns the summary.
function Export-VulnerabilityReport {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Vulnerability = @(),
        [Parameter(Mandatory)][string]$Product,
        [Parameter(Mandatory)][version]$ImageBuild,
        [Parameter(Mandatory)][string[]]$Months,
        [Parameter(Mandatory)][string]$Path
    )
    $summary = Get-VulnerabilitySummary -Vulnerability $Vulnerability
    $columns = 'CVE', 'Title', 'Severity', 'CVSS', 'KB', 'FixedBuild', 'Month'
    $csv = @($Vulnerability | Where-Object { $null -ne $_ } | Select-Object -Property $columns | ConvertTo-Csv -NoTypeInformation)
    if ($csv.Count -eq 0) { $csv = @(($columns | ForEach-Object { '"' + $_ + '"' }) -join ',') }
    [IO.File]::WriteAllLines("$Path.csv", [string[]]$csv, (New-Object Text.UTF8Encoding($true)))
    $document = [ordered]@{
        product    = $Product
        imageBuild = $ImageBuild.ToString()
        source     = 'Microsoft Security Update Guide (MSRC CVRF API v3.0)'
        months     = $Months
        scannedAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        open       = [ordered]@{
            total = $summary.Total; critical = $summary.Critical
            important = $summary.Important; other = $summary.Other
        }
        requiredKb    = $summary.RequiredKb
        requiredBuild = $summary.RequiredBuild
    }
    [IO.File]::WriteAllText("$Path.json", ($document | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
    return $summary
}

Export-ModuleMember -Function ConvertTo-BuildVersion, Get-OpenVulnerability, Get-VulnerabilitySummary,
    Get-MsuInfo, Assert-MsuIntegrity, ConvertFrom-DismWimInfo, Get-MsrcDocument, Export-VulnerabilityReport
