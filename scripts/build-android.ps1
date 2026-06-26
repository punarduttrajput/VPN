<#
.SYNOPSIS
    Build ferrum-client-core for all Android ABIs and generate the Kotlin uniffi bindings.

.DESCRIPTION
    1. Validates that ANDROID_NDK_HOME points to a valid NDK installation.
    2. Cross-compiles ferrum-client-core (--features uniffi,data-plane) for:
         aarch64-linux-android  → arm64-v8a
         armv7-linux-androideabi → armeabi-v7a
         x86_64-linux-android   → x86_64
         i686-linux-android     → x86
    3. Copies the resulting .so files to clients/android/app/src/main/jniLibs/<abi>/.
    4. Runs uniffi-bindgen to write Kotlin bindings to crates/client-core/bindings/kotlin/.

.PARAMETER Release
    Build in release mode (default: debug).

.PARAMETER Abi
    Restrict to a single ABI (e.g. "arm64-v8a"). Builds all four by default.

.EXAMPLE
    # Full release build (set ANDROID_NDK_HOME first):
    $env:ANDROID_NDK_HOME = "C:\Android\Sdk\ndk\27.2.12479018"
    .\scripts\build-android.ps1 -Release

.EXAMPLE
    # Quick debug build for the emulator only:
    .\scripts\build-android.ps1 -Abi x86_64
#>

param(
    [switch]$Release,
    [string]$Abi = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path

# ── NDK validation ─────────────────────────────────────────────────────────────
$NdkHome = $env:ANDROID_NDK_HOME
if (-not $NdkHome) { $NdkHome = $env:NDK_HOME }
if (-not $NdkHome -or -not (Test-Path $NdkHome)) {
    Write-Error @"
ANDROID_NDK_HOME is not set or does not exist.

Install the NDK via Android Studio:
  SDK Manager → SDK Tools → NDK (Side by side) → 27.x

Then set the environment variable:
  `$env:ANDROID_NDK_HOME = "C:\Users\<you>\AppData\Local\Android\Sdk\ndk\27.x.xxxxxxx"

Or install just the NDK via the command-line tools:
  sdkmanager "ndk;27.2.12479018"
"@
}

$ToolchainBin = Join-Path $NdkHome "toolchains\llvm\prebuilt\windows-x86_64\bin"
if (-not (Test-Path $ToolchainBin)) {
    Write-Error "NDK toolchain not found at: $ToolchainBin"
}

Write-Host "NDK : $NdkHome"
Write-Host "Mode: $(if ($Release) { 'release' } else { 'debug' })"

# ── Target map ────────────────────────────────────────────────────────────────
$Targets = [ordered]@{
    "aarch64-linux-android"   = "arm64-v8a"
    "armv7-linux-androideabi" = "armeabi-v7a"
    "x86_64-linux-android"    = "x86_64"
    "i686-linux-android"      = "x86"
}

$ClangForTriple = @{
    "aarch64-linux-android"   = "aarch64-linux-android35-clang"
    "armv7-linux-androideabi" = "armv7a-linux-androideabi35-clang"
    "x86_64-linux-android"    = "x86_64-linux-android35-clang"
    "i686-linux-android"      = "i686-linux-android35-clang"
}

if ($Abi) {
    $triple = ($Targets.GetEnumerator() | Where-Object { $_.Value -eq $Abi } | Select-Object -First 1).Key
    if (-not $triple) { Write-Error "Unknown ABI: $Abi. Valid: $($Targets.Values -join ', ')" }
    $Targets = [ordered]@{ $triple = $Abi }
}

# ── Build ──────────────────────────────────────────────────────────────────────
$Profile    = if ($Release) { "release" } else { "debug" }
$CargoFlags = @("-p", "ferrum-client-core", "--features", "uniffi,data-plane", "--target")
if ($Release) { $CargoFlags += "--release" }

foreach ($entry in $Targets.GetEnumerator()) {
    $triple  = $entry.Key
    $abiDir  = $entry.Value
    $clang   = "$ToolchainBin\$($ClangForTriple[$triple])"
    $tripleU = $triple.ToUpper().Replace("-", "_")

    Write-Host "`n── Building $triple ($abiDir) ──"

    $env:CARGO_NET_OFFLINE                         = "false"
    $env:ANDROID_NDK_HOME                          = $NdkHome
    Set-Item "env:CC_$($triple.Replace('-','_'))"  $clang
    Set-Item "env:CARGO_TARGET_${tripleU}_LINKER"  $clang

    & cargo build @CargoFlags $triple
    if ($LASTEXITCODE -ne 0) { Write-Error "cargo build failed for $triple" }

    $soSrc  = Join-Path $RepoRoot "target\$triple\$Profile\libferrum_client_core.so"
    $jniDir = Join-Path $RepoRoot "clients\android\app\src\main\jniLibs\$abiDir"
    New-Item -ItemType Directory -Force $jniDir | Out-Null

    if (Test-Path $soSrc) {
        Copy-Item $soSrc (Join-Path $jniDir "libferrum_client_core.so") -Force
        Write-Host "  ✓ $soSrc → jniLibs/$abiDir/"
    } else {
        Write-Warning "  ! $soSrc not found"
    }
}

# ── Kotlin bindings ────────────────────────────────────────────────────────────
Write-Host "`n── Generating Kotlin uniffi bindings ──"

$refTriple = "aarch64-linux-android"
$refLib    = Join-Path $RepoRoot "target\$refTriple\$Profile\libferrum_client_core.so"
$outDir    = Join-Path $RepoRoot "crates\client-core\bindings\kotlin"

if (-not (Test-Path $refLib)) {
    Write-Warning "Reference library not found at $refLib; skipping binding generation."
} else {
    New-Item -ItemType Directory -Force $outDir | Out-Null
    & cargo run -p ferrum-client-core --features uniffi --bin uniffi-bindgen `
        -- generate --library $refLib --language kotlin --out-dir $outDir
    if ($LASTEXITCODE -ne 0) { Write-Error "uniffi-bindgen failed" }
    Write-Host "  ✓ Kotlin bindings → $outDir"
}

Write-Host "`nDone. Next: open clients/android/ in Android Studio and run the app."
