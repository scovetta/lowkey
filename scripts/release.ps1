#Requires -Version 7.0
<#
.SYNOPSIS
Validates a release, or bumps, commits, tags, and pushes it with -Publish.
.EXAMPLE
pwsh -File .\scripts\release.ps1 -Version 0.2.0
.EXAMPLE
.\scripts\release.ps1 -Version 0.2.0 -Publish
.NOTES
Requires a clean main branch, an origin remote, and Cargo with rustfmt and Clippy.
Without -Publish (or with -WhatIf), checks run against the current version;
version files, commits, tags, and remote refs are not changed.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')]
    [string] $Version,

    [switch] $Publish
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Invoke-Checked {
    param(
        [string] $Command,
        [string[]] $Arguments,
        [switch] $Capture
    )
    Write-Host "> $Command $($Arguments -join ' ')"
    if ($Capture) {
        $output = & $Command @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$Command $($Arguments -join ' ') failed (exit $LASTEXITCODE)."
        }
        return ($output -join "`n")
    }
    & $Command @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($Arguments -join ' ') failed (exit $LASTEXITCODE)."
    }
}

function Invoke-ReleaseChecks {
    Invoke-Checked cargo @('fmt', '--all', '--check')
    Invoke-Checked cargo @('clippy', '--locked', '--all-targets', '--', '-D', 'warnings')
    Invoke-Checked cargo @('test', '--locked', '--release', '--all-targets')
    Invoke-Checked cargo @('build', '--locked', '--release')
}

$requested = [semver]::Parse($Version)
if ($requested.ToString() -cne $Version) {
    throw "Use a canonical version such as 0.2.0 or 0.2.0-rc.1, without a v prefix or build metadata."
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location -LiteralPath $repo
try {
    Get-Command git, cargo -ErrorAction Stop | Out-Null
    $root = Invoke-Checked git @('rev-parse', '--show-toplevel') -Capture
    if ([IO.Path]::GetFullPath($root) -ne $repo) {
        throw 'The script must be located in the scripts directory of this repository.'
    }
    $branch = Invoke-Checked git @('branch', '--show-current') -Capture
    if ($branch -ne 'main') {
        throw 'Release from the main branch, not a feature branch or detached HEAD.'
    }
    $status = Invoke-Checked git @('status', '--porcelain', '--untracked-files=all') -Capture
    if ($status) {
        throw 'The working tree must be clean. Commit or stash changes, including this script, before releasing.'
    }
    $originalHead = Invoke-Checked git @('rev-parse', 'HEAD') -Capture
    $manifestPath = Join-Path $repo 'Cargo.toml'
    $manifest = [IO.File]::ReadAllText($manifestPath)
    $metadata = Invoke-Checked cargo @('metadata', '--locked', '--no-deps', '--format-version', '1') -Capture |
        ConvertFrom-Json
    $package = @($metadata.packages | Where-Object {
        $_.name -eq 'lowkey-check' -and [IO.Path]::GetFullPath($_.manifest_path) -eq $manifestPath
    })
    if ($package.Count -ne 1) {
        throw 'Expected the lowkey-check package in the root Cargo.toml.'
    }
    $current = [semver]::Parse($package[0].version)
    if ($requested -lt $current) {
        throw "Cannot release ${Version}: Cargo.toml is already at $current."
    }
    $tag = "v$Version"
    if (Invoke-Checked git @('tag', '--list', $tag) -Capture) {
        throw "Local tag $tag already exists; tags are never replaced."
    }
    $null = Invoke-Checked git @('remote', 'get-url', 'origin') -Capture
    if (Invoke-Checked git @('ls-remote', '--tags', 'origin', "refs/tags/$tag") -Capture) {
        throw "Remote tag $tag already exists; tags are never replaced."
    }
    $remoteMain = Invoke-Checked git @('ls-remote', '--heads', 'origin', 'refs/heads/main') -Capture
    if ($remoteMain) {
        $remoteHead = ($remoteMain -split '\s+')[0]
        & git merge-base --is-ancestor $remoteHead HEAD
        if ($LASTEXITCODE -ne 0) {
            throw 'Local main does not contain origin/main. Fetch and integrate its changes before releasing.'
        }
    }

    $publishRelease = $Publish -and $PSCmdlet.ShouldProcess(
        "origin main and $tag",
        "Update version $current -> $Version, validate, commit, create an annotated tag, and push atomically"
    )
    if (-not $publishRelease) {
        Invoke-ReleaseChecks
        Write-Host "Validated the current checkout ($current). Planned release: $tag."
        Write-Host 'No version, commit, tag, or remote changes made. Use -Publish to release.'
        return
    }

    $expectedManifest = $manifest
    if ($Version -cne $package[0].version) {
        $section = [regex]::Match($manifest, '(?ms)^\[package\][^\r\n]*\r?\n.*?(?=^\[|\z)')
        $field = [regex]::Match($section.Value, '(?m)^version\s*=\s*"([^"]+)"')
        if (-not $field.Success -or $field.Groups[1].Value -cne $package[0].version) {
            throw 'Expected a literal version = "..." in the [package] section of Cargo.toml.'
        }
        $offset = $section.Index + $field.Groups[1].Index
        $updated = $manifest.Remove($offset, $field.Groups[1].Length).Insert($offset, $Version)
        [IO.File]::WriteAllText($manifestPath, $updated, [Text.UTF8Encoding]::new($false))
        $expectedManifest = $updated
        # Only refresh workspace versions; do not upgrade locked dependencies.
        Invoke-Checked cargo @('update', '--workspace', '--offline')
    }

    Invoke-ReleaseChecks
    $head = Invoke-Checked git @('rev-parse', 'HEAD') -Capture
    $branch = Invoke-Checked git @('branch', '--show-current') -Capture
    if ($head -ne $originalHead -or $branch -ne 'main') {
        throw 'HEAD or the branch changed during validation. No release commit or tag was created.'
    }
    if ([IO.File]::ReadAllText($manifestPath) -cne $expectedManifest) {
        throw 'Cargo.toml changed unexpectedly during validation. No release commit or tag was created.'
    }
    $untracked = Invoke-Checked git @('ls-files', '--others', '--exclude-standard') -Capture
    $changed = Invoke-Checked git @('diff', '--name-only', 'HEAD') -Capture
    $unexpected = @($changed -split "`n" | Where-Object { $_ -and $_ -notin @('Cargo.toml', 'Cargo.lock') })
    if ($untracked -or $unexpected.Count) {
        throw 'Unexpected files changed during validation. Inspect the working tree before releasing.'
    }
    if ($Version -ceq $package[0].version -and $changed) {
        throw 'Version files changed unexpectedly during validation. Inspect them before releasing.'
    }
    if ($Version -cne $package[0].version) {
        Invoke-Checked git @('add', '--', 'Cargo.toml', 'Cargo.lock')
        Invoke-Checked git @('diff', '--cached', '--check')
        Invoke-Checked git @('commit', '-m', "chore: release $tag")
    }
    $releaseHead = Invoke-Checked git @('rev-parse', 'HEAD') -Capture
    Invoke-Checked git @('tag', '-a', $tag, $releaseHead, '-m', "Release $tag")
    & git push --atomic origin "${releaseHead}:refs/heads/main" "refs/tags/${tag}:refs/tags/$tag" | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Atomic push failed (exit $LASTEXITCODE). Local commit/tag $tag were retained; inspect the failure before retrying. No force push was attempted."
    }
    Write-Host "Pushed main and $tag. GitHub Actions will validate all platforms and publish the release assets."
}
finally {
    Pop-Location
}
