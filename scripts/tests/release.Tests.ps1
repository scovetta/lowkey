#Requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$realCargo = (Get-Command cargo -CommandType Application -TotalCount 1 -ErrorAction Stop).Source
$releaseScript = Join-Path $PSScriptRoot '..\release.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) "lowkey-release-tests-$([guid]::NewGuid().ToString('N'))"
$calls = [Collections.Generic.List[string]]::new()
$failCheck = ''
$mutateManifest = $false
$changeHead = $false

# Exercise real Git and Cargo version/lockfile handling, but stub expensive checks.
function cargo {
    $calls.Add(($args -join ' '))
    $global:LASTEXITCODE = 0
    if ($args[0] -in @('metadata', 'update')) {
        & $realCargo @args
    }
    elseif ($args[0] -eq $failCheck) {
        $global:LASTEXITCODE = 1
    }
    elseif ($args[0] -eq 'test' -and $mutateManifest) {
        [IO.File]::AppendAllText((Join-Path $PWD 'Cargo.toml'), "`n# Unexpected edit`n")
    }
    elseif ($args[0] -eq 'test' -and $changeHead) {
        Invoke-TestGit commit --quiet --allow-empty -m 'Concurrent commit' | Out-Null
    }
}

function Invoke-TestGit {
    $Arguments = @($args | ForEach-Object { $_ })
    $output = & (Get-Command git -CommandType Application -TotalCount 1 -ErrorAction Stop).Source @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git $Arguments failed: $output" }
    return ($output -join "`n")
}

function Assert {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Fails {
    param([scriptblock] $Action, [string] $Message)
    $caught = $null
    try { & $Action } catch { $caught = $_ }
    Assert ($null -ne $caught) "Expected failure: $Message"
    Assert ($caught.ToString().Contains($Message)) "Wrong failure: $caught"
}

function Test-Case {
    param([string] $Name, [scriptblock] $Action)
    $fixture = Join-Path $testRoot $Name
    $remote = Join-Path $testRoot "$Name.git"
    New-Item -ItemType Directory -Path (Join-Path $fixture 'scripts'), (Join-Path $fixture 'src') | Out-Null
    Copy-Item -LiteralPath $releaseScript -Destination (Join-Path $fixture 'scripts\release.ps1')
    [IO.File]::WriteAllText((Join-Path $fixture 'Cargo.toml'), "[package]`nname = `"lowkey-check`"`nversion = `"0.1.0`"`nedition = `"2024`"`n")
    [IO.File]::WriteAllText((Join-Path $fixture 'Cargo.lock'), "version = 4`n`n[[package]]`nname = `"lowkey-check`"`nversion = `"0.1.0`"`n")
    [IO.File]::WriteAllText((Join-Path $fixture 'src\main.rs'), "fn main() {}`n")
    Push-Location -LiteralPath $fixture
    try {
        Invoke-TestGit init --quiet --initial-branch=main | Out-Null
        Invoke-TestGit config user.name 'Release test' | Out-Null
        Invoke-TestGit config user.email 'release-test@example.invalid' | Out-Null
        Invoke-TestGit config commit.gpgsign false | Out-Null
        Invoke-TestGit config tag.gpgsign false | Out-Null
        Invoke-TestGit config core.hooksPath (Join-Path $fixture '.git\hooks') | Out-Null
        Invoke-TestGit add . | Out-Null
        Invoke-TestGit commit --quiet -m 'Test fixture' | Out-Null
        Invoke-TestGit init --bare --quiet --initial-branch=main $remote | Out-Null
        Invoke-TestGit remote add origin $remote | Out-Null
        $calls.Clear()
        & $Action (Join-Path $fixture 'scripts\release.ps1') $remote
        Write-Host "PASS: $Name"
    }
    finally {
        Pop-Location
    }
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    Test-Case 'preview' {
        param($script)
        $head = Invoke-TestGit rev-parse HEAD
        & $script -Version 0.2.0 6>$null
        Assert ((Invoke-TestGit rev-parse HEAD) -eq $head) 'Preview created a commit'
        Assert (-not (Invoke-TestGit status --porcelain)) 'Preview changed files'
        Assert (-not (Invoke-TestGit tag --list)) 'Preview created a tag'
        Assert (-not (Invoke-TestGit ls-remote origin)) 'Preview pushed refs'
        foreach ($check in @('fmt --all --check', 'clippy --locked --all-targets -- -D warnings', 'test --locked --release --all-targets', 'build --locked --release')) {
            Assert ($calls.Contains($check)) "Missing check: $check"
        }
    }
    Test-Case 'what-if' {
        param($script)
        & $script -Version 0.2.0 -Publish -WhatIf 6>$null
        Assert (-not (Invoke-TestGit status --porcelain)) 'WhatIf changed files'
        Assert (-not (Invoke-TestGit tag --list)) 'WhatIf created a tag'
        Assert (-not (Invoke-TestGit ls-remote origin)) 'WhatIf pushed refs'
    }
    Test-Case 'publish' {
        param($script)
        & $script -Version 0.2.0-rc.1 -Publish -Confirm:$false 6>$null
        Assert ((Get-Content Cargo.toml -Raw).Contains('version = "0.2.0-rc.1"')) 'Manifest not bumped'
        Assert ((Get-Content Cargo.lock -Raw).Contains('version = "0.2.0-rc.1"')) 'Lockfile not bumped'
        Assert ((Invoke-TestGit rev-list --count HEAD) -eq '2') 'Expected one version commit'
        Assert ((Invoke-TestGit cat-file -t refs/tags/v0.2.0-rc.1) -eq 'tag') 'Tag is not annotated'
        $head = Invoke-TestGit rev-parse HEAD
        Assert ((Invoke-TestGit ls-remote --heads origin refs/heads/main).StartsWith($head)) 'Main not pushed'
        Assert ([bool](Invoke-TestGit ls-remote --tags origin refs/tags/v0.2.0-rc.1)) 'Tag not pushed'
        Assert (-not (Invoke-TestGit status --porcelain)) 'Publish left a dirty tree'
    }
    Test-Case 'initial-version' {
        param($script)
        & $script -Version 0.1.0 -Publish -Confirm:$false 6>$null
        Assert ((Invoke-TestGit rev-list --count HEAD) -eq '1') 'Same-version release created a needless commit'
        Assert ([bool](Invoke-TestGit tag --list v0.1.0)) 'Initial release tag missing'
    }
    Test-Case 'dirty-tree' {
        param($script)
        [IO.File]::WriteAllText((Join-Path $PWD 'unexpected.txt'), 'uncommitted')
        Assert-Fails { & $script -Version 0.2.0 -Publish -Confirm:$false 6>$null } 'working tree must be clean'
        Assert (-not $calls.Count) 'Checks ran despite dirty input'
    }
    Test-Case 'wrong-branch' {
        param($script)
        Invoke-TestGit switch --quiet -c feature | Out-Null
        Assert-Fails { & $script -Version 0.2.0 6>$null } 'Release from the main branch'
    }
    Test-Case 'versions-and-tags' {
        param($script)
        Assert-Fails { & $script -Version 0.0.9 6>$null } 'Cannot release'
        foreach ($version in @('v0.2.0', '01.2.3', '1.2.3-rc.01', '1.2.3+build')) {
            Assert-Fails { & $script -Version $version 6>$null } ''
        }
        Invoke-TestGit tag v0.2.0 | Out-Null
        Assert-Fails { & $script -Version 0.2.0 6>$null } 'Local tag'
        Invoke-TestGit push origin refs/tags/v0.2.0 | Out-Null
        Invoke-TestGit tag -d v0.2.0 | Out-Null
        Assert-Fails { & $script -Version 0.2.0 6>$null } 'Remote tag'
        Assert (-not (Invoke-TestGit status --porcelain)) 'Rejected inputs changed files'
    }
    Test-Case 'remote-ahead' {
        param($script)
        Invoke-TestGit switch --quiet -c advance | Out-Null
        Invoke-TestGit commit --quiet --allow-empty -m 'Remote advancement' | Out-Null
        Invoke-TestGit push origin HEAD:refs/heads/main | Out-Null
        Invoke-TestGit switch --quiet main | Out-Null
        Assert-Fails { & $script -Version 0.2.0 6>$null } 'does not contain origin/main'
    }
    Test-Case 'failed-check' {
        param($script)
        $script:failCheck = 'test'
        try {
            Assert-Fails { & $script -Version 0.2.0 -Publish -Confirm:$false 6>$null } 'failed (exit 1)'
        }
        finally { $script:failCheck = '' }
        Assert ((Invoke-TestGit rev-list --count HEAD) -eq '1') 'Failed checks created a commit'
        Assert (-not (Invoke-TestGit tag --list)) 'Failed checks created a tag'
        Assert (-not (Invoke-TestGit ls-remote origin)) 'Failed checks pushed refs'
        Assert ([bool](Invoke-TestGit status --porcelain)) 'Expected version edits to remain visible after failure'
    }
    Test-Case 'failed-push' {
        param($script, $remote)
        $hooks = Join-Path $remote 'hooks'
        Invoke-TestGit --git-dir $remote config core.hooksPath $hooks | Out-Null
        $hook = Join-Path $hooks 'update'
        [IO.File]::WriteAllText($hook, "#!/bin/sh`ncase `"`$1`" in refs/tags/*) exit 1;; esac`nexit 0`n")
        if (-not $IsWindows) {
            & chmod +x $hook
            Assert ($LASTEXITCODE -eq 0) 'Cannot enable test hook'
        }
        Assert-Fails { & $script -Version 0.2.0 -Publish -Confirm:$false 6>$null } 'Atomic push failed'
        Assert ((Invoke-TestGit rev-list --count HEAD) -eq '2') 'Local release commit was lost'
        Assert ([bool](Invoke-TestGit tag --list v0.2.0)) 'Local tag was lost'
        Assert (-not (Invoke-TestGit ls-remote origin)) 'Failed atomic push updated remote refs'
    }
    Test-Case 'manifest-changed-during-checks' {
        param($script)
        $script:mutateManifest = $true
        try {
            Assert-Fails { & $script -Version 0.2.0 -Publish -Confirm:$false 6>$null } 'Cargo.toml changed unexpectedly'
        }
        finally { $script:mutateManifest = $false }
        Assert ((Invoke-TestGit rev-list --count HEAD) -eq '1') 'Unexpected manifest was committed'
        Assert (-not (Invoke-TestGit tag --list)) 'Unexpected manifest was tagged'
    }
    Test-Case 'head-changed-during-checks' {
        param($script)
        $script:changeHead = $true
        try {
            Assert-Fails { & $script -Version 0.2.0 -Publish -Confirm:$false 6>$null } 'HEAD or the branch changed'
        }
        finally { $script:changeHead = $false }
        Assert ((Invoke-TestGit rev-list --count HEAD) -eq '2') 'Expected only the simulated concurrent commit'
        Assert (-not (Invoke-TestGit tag --list)) 'Concurrent commit was tagged'
    }
    Write-Host 'All release-script tests passed.'
}
finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
