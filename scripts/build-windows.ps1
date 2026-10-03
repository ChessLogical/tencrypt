<#
.SYNOPSIS
Builds the native Windows executable with Rust 1.99.0 and MSVC.
.EXAMPLE
.\scripts\build-windows.ps1
.EXAMPLE
.\scripts\build-windows.ps1 -Native
.EXAMPLE
.\scripts\build-windows.ps1 -Target aarch64-pc-windows-msvc
#>
[CmdletBinding()]
param(
    [string]$Target = 'x86_64-pc-windows-msvc',
    [switch]$Native
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Toolchain = '1.99.0'
$ProjectRoot = Split-Path -Parent $PSScriptRoot

if ($env:OS -ne 'Windows_NT') {
    throw 'Run this script on Windows; use build-linux.sh on Linux.'
}
if ($Target -notmatch '^[A-Za-z0-9_]+-pc-windows-msvc$') {
    throw "Expected a Windows MSVC target; received: $Target"
}

foreach ($RequiredTool in @('rustup', 'rustc', 'cargo')) {
    if (-not (Get-Command $RequiredTool -ErrorAction SilentlyContinue)) {
        throw "$RequiredTool is missing; install Rust through rustup first."
    }
}

$SavedRustFlags = [Environment]::GetEnvironmentVariable('RUSTFLAGS', 'Process')
Push-Location -LiteralPath $ProjectRoot
try {
    $CompilerInfo = & rustc "+$Toolchain" -vV
    if ($LASTEXITCODE -ne 0) {
        throw "Install the required toolchain: rustup toolchain install $Toolchain --profile minimal --component rustfmt"
    }

    if ($Native) {
        $CompilerHostLine = @($CompilerInfo | Where-Object { $_ -like 'host: *' })
        if ($CompilerHostLine.Count -ne 1) {
            throw 'Could not determine the Rust compiler host target.'
        }
        $CompilerHost = $CompilerHostLine[0].Substring(6).Trim()
        if ($Target -ne $CompilerHost) {
            throw "-Native requires target $Target to match compiler host $CompilerHost."
        }
        if ([string]::IsNullOrWhiteSpace($SavedRustFlags)) {
            $env:RUSTFLAGS = '-C target-cpu=native'
        }
        else {
            $env:RUSTFLAGS = "$SavedRustFlags -C target-cpu=native"
        }
    }

    & rustup target add --toolchain $Toolchain $Target
    if ($LASTEXITCODE -ne 0) {
        throw "Installing Rust target $Target failed."
    }

    $BuildArgs = @(
        "+$Toolchain", 'build', '--locked', '--release',
        '--target', $Target,
        '--target-dir', (Join-Path $ProjectRoot 'target'),
        '--no-default-features', '--features', 'windows-bin',
        '--bin', 'tencrypt-windows'
    )
    & cargo @BuildArgs
    if ($LASTEXITCODE -ne 0) {
        throw 'The Windows release build failed.'
    }

    $OutputDirectory = Join-Path $ProjectRoot 'dist/windows'
    $BuiltExecutable = Join-Path $ProjectRoot "target/$Target/release/tencrypt-windows.exe"
    $OutputExecutable = Join-Path $OutputDirectory 'tencrypt-windows.exe'
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item -LiteralPath $BuiltExecutable -Destination $OutputExecutable -Force
    Write-Host "Built $OutputExecutable"
}
finally {
    [Environment]::SetEnvironmentVariable('RUSTFLAGS', $SavedRustFlags, 'Process')
    Pop-Location
}
