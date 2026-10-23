#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$pwsh = (Get-Command pwsh -CommandType Application -TotalCount 1 -ErrorAction Stop).Source
$runner = Join-Path $PSScriptRoot '..\scan-ccadb.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "lowkey-ccadb-tests-$([guid]::NewGuid().ToString('N'))"
$oldFixture = $env:LOWKEY_TEST_FIXTURE
New-Item -ItemType Directory -Path $root | Out-Null

function Assert {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-Case {
    param(
        [string] $Name,
        [hashtable] $Options,
        [hashtable] $Codes = @{},
        [switch] $FailDownload,
        [ValidateSet('normal', 'empty', 'missing-column', 'blank')]
        [string] $Report = 'normal'
    )
    $fixture = Join-Path $root $Name
    New-Item -ItemType Directory -Path $fixture | Out-Null
    $fake = Join-Path $fixture 'fake lowkey.ps1'
    @'
$arguments = @($args)
$patternIndex = [Array]::IndexOf($arguments, '--ec-pattern')
$id = 'baseline'
if ($patternIndex -ge 0) {
    $widthIndex = [Array]::IndexOf($arguments, '--filter-bits')
    $id = "$($arguments[$widthIndex + 1])-$($arguments[$patternIndex + 1])"
}
@{ Id = $id; Arguments = $arguments } | ConvertTo-Json -Compress |
    Add-Content -LiteralPath (Join-Path $env:LOWKEY_TEST_FIXTURE 'calls.jsonl')
$codes = Get-Content -LiteralPath (Join-Path $env:LOWKEY_TEST_FIXTURE 'codes.json') -Raw |
    ConvertFrom-Json -AsHashtable
$code = if ($codes.ContainsKey($id)) { [int] $codes[$id] } else { 0 }
Write-Output "stdout $id"
if ($code -gt 1) { Write-Error "stderr $id" -ErrorAction Continue }
exit $code
'@ | Set-Content -LiteralPath $fake
    $driver = Join-Path $fixture 'driver.ps1'
    @'
param([string] $Runner, [string] $Config)
function Invoke-WebRequest {
    param($Uri, $OutFile, $TimeoutSec, $MaximumRetryCount, $RetryIntervalSec)
    if (Test-Path -LiteralPath (Join-Path $env:LOWKEY_TEST_FIXTURE 'fail-download')) {
        throw 'offline download failure'
    }
    Add-Content -LiteralPath (Join-Path $env:LOWKEY_TEST_FIXTURE 'downloads.log') -Value $Uri
    Copy-Item -LiteralPath (Join-Path $env:LOWKEY_TEST_FIXTURE 'source.csv') -Destination $OutFile
}
$options = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json -AsHashtable
& $Runner @options
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $driver
    $source = Join-Path $fixture 'source.csv'
    @(
        [pscustomobject] @{
            'Certificate Name' = 'test, "quoted" name'
            'Public Key' = "-----BEGIN PUBLIC KEY-----`nfixture`n-----END PUBLIC KEY-----"
        },
        [pscustomobject] @{ 'Certificate Name' = 'blank'; 'Public Key' = '' }
    ) | Export-Csv -LiteralPath $source -NoTypeInformation
    switch ($Report) {
        'empty' { '"Certificate Name","Public Key"' | Set-Content -LiteralPath $source }
        'missing-column' { @('"Name"', '"not a certificate report"') | Set-Content -LiteralPath $source }
        'blank' {
            [pscustomobject] @{ 'Certificate Name' = 'empty'; 'Public Key' = '' } |
                Export-Csv -LiteralPath $source -NoTypeInformation
        }
    }
    $Codes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $fixture 'codes.json')
    if ($FailDownload) {
        New-Item -ItemType File -Path (Join-Path $fixture 'fail-download') | Out-Null
    }
    $Options.Binary = $fake
    $Options.OutputDirectory = Join-Path $fixture 'results'
    $config = Join-Path $fixture 'config.json'
    $Options | ConvertTo-Json | Set-Content -LiteralPath $config
    $env:LOWKEY_TEST_FIXTURE = $fixture
    $output = & $pwsh -NoProfile -File $driver -Runner $runner -Config $config 2>&1
    $code = $LASTEXITCODE
    $directories = @(Get-ChildItem -LiteralPath $Options.OutputDirectory -Directory -ErrorAction SilentlyContinue)
    $calls = @()
    $callPath = Join-Path $fixture 'calls.jsonl'
    if (Test-Path -LiteralPath $callPath) {
        $calls = @(Get-Content -LiteralPath $callPath | ConvertFrom-Json)
    }
    [pscustomobject] @{
        Code = $code
        Output = $output -join "`n"
        Fixture = $fixture
        Directory = if ($directories.Count) { $directories[0].FullName } else { $null }
        Calls = $calls
    }
}

try {
    $case = Invoke-Case 'default-plan' @{ Year = '2000-2001' }
    Assert ($case.Code -eq 0) $case.Output
    Assert ($case.Calls.Count -eq 33) 'Expected baseline and four passes for each of eight widths'
    Assert (@(Get-Content (Join-Path $case.Fixture 'downloads.log')).Count -eq 2) 'Reports were downloaded repeatedly'
    $snapshot = @(Import-Csv -LiteralPath (Join-Path $case.Directory 'ccadb.csv'))
    Assert ($snapshot.Count -eq 2) 'Snapshot lost cross-year records or retained blank keys'
    Assert ($snapshot[0].'Certificate Name' -eq '2000 row 2 test, "quoted" name') 'Snapshot lost source labels'
    Assert ($snapshot[1].'Certificate Name' -like '2001 row 2*') 'Snapshot lost year'
    Assert ($snapshot[0].'Public Key'.Contains("`nfixture`n")) 'Snapshot damaged multiline PEM'
    $summary = @(Import-Csv -LiteralPath (Join-Path $case.Directory 'summary.csv'))
    Assert ($summary.Count -eq 33) 'Incomplete summary'
    foreach ($call in $case.Calls) {
        $arguments = @($call.Arguments)
        Assert ($arguments -contains '--quiet') 'Missing quiet mode'
        Assert ($arguments -notcontains '--ct-details') 'Unexpected CT request'
        Assert ($arguments[-1] -eq (Join-Path $case.Directory 'ccadb.csv')) 'Passes did not share one corpus'
        $fermatIndex = [Array]::IndexOf($arguments, '--fermat-steps')
        if ($call.Id -eq 'baseline') {
            Assert ($arguments[$fermatIndex + 1] -eq '1000') 'Missing baseline Fermat checks'
            Assert ($arguments[1] -eq '0-32767') 'Unexpected baseline range'
        }
        else {
            $widthIndex = [Array]::IndexOf($arguments, '--filter-bits')
            $patternIndex = [Array]::IndexOf($arguments, '--ec-pattern')
            $bitsIndex = [Array]::IndexOf($arguments, '--pattern-bits')
            $budgetIndex = [Array]::IndexOf($arguments, '--max-candidates')
            $width = [int] $arguments[$widthIndex + 1]
            $pattern = $arguments[$patternIndex + 1]
            $expected = if ($pattern -in @('zeros', 'ones')) { $width - 1 } else { $width - 10 }
            Assert ([int] $arguments[$bitsIndex + 1] -eq $expected) 'Incorrect width-specific threshold'
            Assert ($arguments[$budgetIndex + 1] -eq '8192') 'Missing candidate budget'
            Assert ($arguments[$fermatIndex + 1] -eq '0') 'Repeated Fermat work'
        }
    }
    Write-Host 'PASS: bounded default plan and single combined snapshot'

    $reuse = Join-Path $case.Directory 'ccadb.csv'
    foreach ($offset in @(0, 8, 12)) {
        $case = Invoke-Case "offset-$offset" @{
            InputCsv = $reuse
            Widths = @(256, 384)
            RunFreeBits = $offset
            MaxCandidates = 32768
        }
        Assert ($case.Code -eq 0) $case.Output
        Assert ($case.Calls.Count -eq 9) 'Custom offset changed pass count'
        foreach ($call in ($case.Calls | Where-Object Id -ne 'baseline')) {
            $arguments = @($call.Arguments)
            $widthIndex = [Array]::IndexOf($arguments, '--filter-bits')
            $patternIndex = [Array]::IndexOf($arguments, '--ec-pattern')
            $bitsIndex = [Array]::IndexOf($arguments, '--pattern-bits')
            $budgetIndex = [Array]::IndexOf($arguments, '--max-candidates')
            $width = [int] $arguments[$widthIndex + 1]
            $pattern = $arguments[$patternIndex + 1]
            $expected = if ($pattern -in @('zeros', 'ones')) { $width - 1 } else { $width - $offset }
            Assert ([int] $arguments[$bitsIndex + 1] -eq $expected) 'Custom offset was ignored or affected zeros/ones'
            Assert ($arguments[$budgetIndex + 1] -eq '32768') 'Custom budget was ignored'
        }
    }
    Write-Host 'PASS: configurable run offset and candidate budget'

    foreach ($options in @(
        @{ RunFreeBits = -1 },
        @{ RunFreeBits = 160 },
        @{ RunFreeBits = 521 },
        @{ MaxCandidates = 0 }
    )) {
        $options.Year = '2025'
        $case = Invoke-Case "invalid-settings-$([guid]::NewGuid().ToString('N'))" $options
        Assert ($case.Code -eq 2) 'Invalid run offset/budget was accepted'
        Assert ($case.Calls.Count -eq 0) 'Invalid settings started scans'
        Assert (-not (Test-Path (Join-Path $case.Fixture 'downloads.log'))) 'Invalid settings started downloads'
    }
    Write-Host 'PASS: invalid offsets and budgets fail before network access'

    foreach ($codes in @(
        @{ baseline = 1 },
        @{ '384-zeros' = 2; '384-one-run' = 1 },
        @{ baseline = 1; '384-one-run' = 2 },
        @{ '384-zeros' = 7 }
    )) {
        $name = "statuses-$([guid]::NewGuid().ToString('N'))"
        $case = Invoke-Case $name @{ InputCsv = $reuse; Widths = @(384, 384); Threads = 2 } $codes
        $expected = if (@($codes.Values | Where-Object { $_ -gt 1 }).Count) { 2 } else { 1 }
        Assert ($case.Code -eq $expected) "Wrong aggregate exit: $($case.Output)"
        Assert ($case.Calls.Count -eq 5) 'Finding/error stopped later passes or duplicate widths were retained'
        Assert (-not (Test-Path (Join-Path $case.Fixture 'downloads.log'))) 'Snapshot reuse downloaded reports'
        $summary = @(Import-Csv -LiteralPath (Join-Path $case.Directory 'summary.csv'))
        Assert ($summary.Count -eq 5) 'Error lost pass results'
        Assert ((Get-Content -LiteralPath $summary[0].Stdout -Raw).Contains('stdout baseline')) 'Missing stdout log'
        if ($expected -eq 2) {
            Assert ($case.Output.Contains('stderr')) 'Scan errors were not visible'
        }
    }
    Write-Host 'PASS: snapshot reuse, width deduplication, logs, findings and error precedence'

    $case = Invoke-Case 'download-failure' @{ Year = '2025'; Widths = @(256) } -FailDownload
    Assert ($case.Code -eq 2) 'Download failure did not return exit 2'
    Assert ($case.Output.Contains('offline download failure')) 'Download error was hidden'
    Assert ($case.Calls.Count -eq 0) 'Scanned an incomplete download'
    Assert (-not (Test-Path (Join-Path $case.Directory 'ccadb.csv'))) 'Published an incomplete snapshot'
    Write-Host 'PASS: failed downloads do not start scans'

    foreach ($report in @('empty', 'missing-column', 'blank')) {
        $case = Invoke-Case "report-$report" @{ Year = '2025'; Widths = @(256) } -Report $report
        Assert ($case.Code -eq 2) "Accepted $report report: $($case.Output)"
        Assert ($case.Calls.Count -eq 0) "Scanned a $report report"
        Assert (-not (Test-Path (Join-Path $case.Directory 'ccadb.csv'))) 'Published an unusable snapshot'
    }
    Write-Host 'PASS: unusable reports fail before scanning'

    $case = Invoke-Case 'invalid-year' @{ Year = '2001-2000' }
    Assert ($case.Code -eq 2) 'Reversed years were accepted'
    Assert ($case.Calls.Count -eq 0) 'Invalid years started scans'
    Assert (-not (Test-Path (Join-Path $case.Fixture 'downloads.log'))) 'Invalid years started downloads'
    Write-Host 'PASS: invalid years fail before network access'
}
finally {
    $env:LOWKEY_TEST_FIXTURE = $oldFixture
    Remove-Item -LiteralPath $root -Recurse -Force
}

# CI propagates LASTEXITCODE; expected subprocess failures must not fail a successful suite.
$global:LASTEXITCODE = 0
