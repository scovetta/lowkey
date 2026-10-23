#Requires -Version 7.0
<#
.SYNOPSIS
Scans a saved CCADB corpus with bounded range and full-width EC pattern searches.
.EXAMPLE
pwsh -File .\scripts\scan-ccadb.ps1 -Year 2025
.EXAMPLE
pwsh -File .\scripts\scan-ccadb.ps1 -InputCsv .\ccadb.csv -Widths 256,384
.EXAMPLE
pwsh -File .\scripts\scan-ccadb.ps1 -Year 2025 -RunFreeBits 12 -MaxCandidates 32768
.NOTES
Downloads each selected annual report once and combines them for cross-year RSA
batch GCD. Each pass saves stdout/stderr and a row in summary.csv.
Exit codes: 0 = no finding, 1 = findings, 2 = any download or scan error.
#>
[CmdletBinding(DefaultParameterSetName = 'Download')]
param(
    [Parameter(ParameterSetName = 'Download')]
    [ValidatePattern('^(?:[0-9]{4}|[0-9]{4}-[0-9]{4}|-[0-9]{4}|[0-9]{4}-)$')]
    [string] $Year = '1999-',

    [Parameter(Mandatory, ParameterSetName = 'Existing')]
    [string] $InputCsv,

    [ValidateSet(160, 192, 224, 256, 320, 384, 512, 521)]
    [int[]] $Widths = @(160, 192, 224, 256, 320, 384, 512, 521),

    [ValidateRange(1, 256)]
    [int] $Threads = [Math]::Min(4, [Environment]::ProcessorCount),

    # Run patterns require at least (width - RunFreeBits) consecutive matching bits.
    [int] $RunFreeBits = 10,

    [UInt64] $MaxCandidates = 8192,

    [string] $Binary,

    [string] $OutputDirectory = (Join-Path $PSScriptRoot '..\target\ccadb-scans')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Save-CcadbSnapshot {
    param([int] $FirstYear, [int] $LastYear, [string] $Directory)

    $partial = Join-Path $Directory 'ccadb.partial.csv'
    $snapshot = Join-Path $Directory 'ccadb.csv'
    & {
        foreach ($reportYear in $FirstYear..$LastYear) {
            $report = Join-Path $Directory "$reportYear.csv"
            $uri = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear=$reportYear"
            Write-Host "Downloading CCADB $reportYear..."
            Invoke-WebRequest -Uri $uri -OutFile $report -TimeoutSec 120 `
                -MaximumRetryCount 2 -RetryIntervalSec 5
            $records = @(Import-Csv -LiteralPath $report)
            if ($records.Count -eq 0) {
                throw "CCADB $reportYear returned an empty report; no scans were started."
            }
            $headers = @($records[0].PSObject.Properties.Name)
            $column = $headers | Where-Object { $_.Trim() -ilike '*public key*' } | Select-Object -First 1
            if (-not $column) {
                $column = $headers | Where-Object { $_.Trim() -ilike '*pem*' } | Select-Object -First 1
            }
            if (-not $column) {
                $column = $headers | Where-Object { $_.Trim() -ieq 'certificate' } | Select-Object -First 1
            }
            if (-not $column) {
                throw "CCADB $reportYear has no public key/certificate column."
            }
            $nameColumns = @($headers | Where-Object {
                $_.Trim() -in @('CA Owner', 'Certificate Name', 'SHA-256 Fingerprint')
            })
            $row = 1
            foreach ($record in $records) {
                $row++
                $value = [string] $record.$column
                if ([string]::IsNullOrWhiteSpace($value)) { continue }
                $name = ($nameColumns | ForEach-Object { $record.$_ }) -join '/'
                [pscustomobject] @{
                    'Certificate Name' = "$reportYear row $row $name".Trim()
                    'Public Key' = $value.Trim()
                }
            }
        }
    } | Export-Csv -LiteralPath $partial -NoTypeInformation -Encoding utf8
    if (-not (Test-Path -LiteralPath $partial) -or (Get-Item -LiteralPath $partial).Length -eq 0) {
        throw 'The selected CCADB reports contained no keys or certificates.'
    }
    Move-Item -LiteralPath $partial -Destination $snapshot
    return $snapshot
}

try {
    if (-not $Widths -or $Widths.Count -eq 0) {
        throw 'Select at least one EC width.'
    }
    $minimumWidth = ($Widths | Measure-Object -Minimum).Minimum
    if ($RunFreeBits -lt 0 -or $RunFreeBits -ge $minimumWidth) {
        throw "-RunFreeBits must be nonnegative and smaller than every selected width (minimum $minimumWidth)."
    }
    if ($MaxCandidates -eq 0) {
        throw '-MaxCandidates must be positive.'
    }
    if (-not $Binary) {
        $name = if ($IsWindows) { 'lowkey-check.exe' } else { 'lowkey-check' }
        $Binary = Join-Path $PSScriptRoot "..\target\release\$name"
        if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
            $Binary = 'lowkey-check'
        }
    }
    $executable = (Get-Command $Binary -CommandType Application, ExternalScript `
        -TotalCount 1 -ErrorAction Stop).Source
    $firstYear = 1999
    $lastYear = [DateTime]::UtcNow.Year
    if ($PSCmdlet.ParameterSetName -eq 'Download') {
        if ($Year.Contains('-')) {
            $ends = $Year.Split('-')
            if ($ends[0]) { $firstYear = [int] $ends[0] }
            if ($ends[1]) { $lastYear = [int] $ends[1] }
        }
        else {
            $firstYear = $lastYear = [int] $Year
        }
        if ($firstYear -lt 1999 -or $lastYear -gt [DateTime]::UtcNow.Year -or $firstYear -gt $lastYear) {
            throw "CCADB years must be ordered and between 1999 and $([DateTime]::UtcNow.Year)."
        }
    }
    elseif (-not (Test-Path -LiteralPath $InputCsv -PathType Leaf) -or
        [IO.Path]::GetExtension($InputCsv) -ine '.csv') {
        throw '-InputCsv must name an existing .csv snapshot.'
    }
    $runName = "$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $directory = New-Item -ItemType Directory -Path (Join-Path $OutputDirectory $runName)
    Write-Host "Results: $($directory.FullName)"
    if ($PSCmdlet.ParameterSetName -eq 'Existing') {
        $snapshot = Join-Path $directory.FullName 'ccadb.csv'
        Copy-Item -LiteralPath $InputCsv -Destination $snapshot
    }
    else {
        $snapshot = Save-CcadbSnapshot $firstYear $lastYear $directory.FullName
    }

    $passes = [Collections.Generic.List[object]]::new()
    $passes.Add(@{
        Name = 'baseline'
        Arguments = @('--range', '0-32767', '--fermat-steps', '1000')
    })
    foreach ($width in ($Widths | Sort-Object -Unique)) {
        foreach ($pattern in @('zeros', 'ones', 'zero-run', 'one-run')) {
            $bits = if ($pattern -in @('zeros', 'ones')) { $width - 1 } else { $width - $RunFreeBits }
            $passes.Add(@{
                Name = "$width-$pattern"
                Arguments = @(
                    '--filter-bits', "$width", '--ec-pattern', $pattern,
                    '--pattern-bits', "$bits", '--max-candidates', "$MaxCandidates",
                    '--fermat-steps', '0'
                )
            })
        }
    }
    $status = 0
    $summary = Join-Path $directory.FullName 'summary.csv'
    foreach ($pass in $passes) {
        $arguments = @($pass.Arguments) + @('--threads', "$Threads", '--quiet', $snapshot)
        $stdout = Join-Path $directory.FullName "$($pass.Name).stdout.log"
        $stderr = Join-Path $directory.FullName "$($pass.Name).stderr.log"
        Write-Host "> $executable $($arguments -join ' ')"
        $global:LASTEXITCODE = 0
        & $executable @arguments 1> $stdout 2> $stderr
        $code = $LASTEXITCODE
        $result = switch ($code) {
            0 { 'no finding' }
            1 { 'finding' }
            default { 'error' }
        }
        [pscustomobject] @{
            Pass = $pass.Name
            Result = $result
            ExitCode = $code
            Stdout = $stdout
            Stderr = $stderr
        } | Export-Csv -LiteralPath $summary -NoTypeInformation -Encoding utf8 -Append
        Write-Host "$($pass.Name): $result (exit $code)"
        if ($code -notin @(0, 1)) {
            $status = 2
            Get-Content -LiteralPath $stderr | ForEach-Object { Write-Host $_ }
        }
        elseif ($code -eq 1 -and $status -eq 0) {
            $status = 1
        }
    }
    Write-Host "Finished: exit $status. Summary: $summary"
    exit $status
}
catch {
    Write-Error $_ -ErrorAction Continue
    exit 2
}
