[CmdletBinding()]
param(
  [switch]$Force,
  [string]$JadxVersion = "1.5.3",
  [string]$AndroidBuildTools = "35.0.0"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $projectRoot ".toolcache"
$downloadRoot = Join-Path $toolRoot "downloads"
$sdkRoot = Join-Path $toolRoot "android-sdk"
$binRoot = Join-Path $toolRoot "bin"

function Get-Download {
  param([string]$Uri, [string]$Destination)
  if ($Force -or -not (Test-Path $Destination)) {
    Write-Host "Downloading $([IO.Path]::GetFileName($Destination))..."
    $temporary = "$Destination.part"
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    # curl follows GitHub redirects and can resume a partially downloaded archive.
    # It is more reliable than the legacy PowerShell web request stream for these
    # large release files.
    & curl.exe --fail --location --retry 5 --retry-all-errors --retry-delay 2 --continue-at - --output $temporary $Uri
    if ($LASTEXITCODE -ne 0) { throw "Download failed: $Uri" }
    if (-not (Test-Path $temporary) -or (Get-Item $temporary).Length -lt 1024) {
      throw "Downloaded file is missing or unexpectedly small: $Uri"
    }
    # A real-time scanner can briefly hold a just-downloaded executable archive.
    # Retry the atomic rename rather than accepting a partial file.
    $moved = $false
    foreach ($attempt in 1..12) {
      try {
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
        $moved = $true
        break
      }
      catch {
        if ($attempt -eq 12) { throw }
        Start-Sleep -Seconds 1
      }
    }
    if (-not $moved) { throw "Could not finalize downloaded file: $Uri" }
  }
}

function Find-FirstFile {
  param([string]$Root, [string]$Name)
  return Get-ChildItem -Path $Root -Filter $Name -Recurse -File | Select-Object -First 1
}

New-Item -ItemType Directory -Force -Path $toolRoot, $downloadRoot, $sdkRoot, $binRoot | Out-Null

# JADX ships with a private JRE here, avoiding a machine-wide Java installation.
$jadxArchive = Join-Path $downloadRoot "jadx-gui-$JadxVersion-with-jre-win.zip"
$jadxHome = Join-Path $toolRoot "jadx"
if ($Force -or -not (Test-Path (Join-Path $jadxHome "jre\bin\java.exe"))) {
  Get-Download "https://github.com/skylot/jadx/releases/download/v$JadxVersion/jadx-gui-$JadxVersion-with-jre-win.zip" $jadxArchive
  Remove-Item -LiteralPath $jadxHome -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $jadxHome | Out-Null
  Expand-Archive -LiteralPath $jadxArchive -DestinationPath $jadxHome -Force
}

$jadxCliArchive = Join-Path $downloadRoot "jadx-$JadxVersion.zip"
$jadxCliHome = Join-Path $toolRoot "jadx-cli"
if ($Force -or -not (Test-Path $jadxCliHome) -or -not (Find-FirstFile $jadxCliHome "jadx.bat")) {
  Get-Download "https://github.com/skylot/jadx/releases/download/v$JadxVersion/jadx-$JadxVersion.zip" $jadxCliArchive
  Remove-Item -LiteralPath $jadxCliHome -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $jadxCliHome | Out-Null
  Expand-Archive -LiteralPath $jadxCliArchive -DestinationPath $jadxCliHome -Force
}

$jadx = Find-FirstFile $jadxCliHome "jadx.bat"
$java = Find-FirstFile $jadxHome "java.exe"
if (-not $jadx -or -not $java) { throw "JADX installation did not contain jadx.bat and a bundled java.exe." }
$env:JAVA_HOME = $java.Directory.Parent.FullName
$env:Path = "$($env:JAVA_HOME)\bin;$env:Path"

# Android's official command-line tools install the verifier, AAPT and ADB locally.
$androidArchive = Join-Path $downloadRoot "commandlinetools-win-13114758_latest.zip"
$cmdlineHome = Join-Path $sdkRoot "cmdline-tools\latest"
if ($Force -or -not (Test-Path (Join-Path $cmdlineHome "bin\sdkmanager.bat"))) {
  Get-Download "https://dl.google.com/android/repository/commandlinetools-win-13114758_latest.zip" $androidArchive
  $extractRoot = Join-Path $toolRoot "android-commandline-extract"
  Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
  Expand-Archive -LiteralPath $androidArchive -DestinationPath $extractRoot -Force
  $source = Get-ChildItem -Path $extractRoot -Directory -Recurse | Where-Object { Test-Path (Join-Path $_.FullName "bin\sdkmanager.bat") } | Select-Object -First 1
  if (-not $source) { throw "Android command-line tools archive did not contain sdkmanager.bat." }
  Remove-Item -LiteralPath $cmdlineHome -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $cmdlineHome) | Out-Null
  Move-Item -LiteralPath $source.FullName -Destination $cmdlineHome
}

$sdkManager = Join-Path $cmdlineHome "bin\sdkmanager.bat"
$answerFile = Join-Path $toolRoot "sdk-licenses.txt"
Set-Content -LiteralPath $answerFile -Value ((1..160 | ForEach-Object { "y" }) -join [Environment]::NewLine)
cmd.exe /d /c "type `"$answerFile`" | `"$sdkManager`" --sdk_root=`"$sdkRoot`" --licenses" | Out-Host
& $sdkManager "--sdk_root=$sdkRoot" "platform-tools" "build-tools;$AndroidBuildTools"
if ($LASTEXITCODE -ne 0) { throw "Android SDK package installation failed." }

$aapt2 = Find-FirstFile (Join-Path $sdkRoot "build-tools") "aapt2.exe"
$aapt = Find-FirstFile (Join-Path $sdkRoot "build-tools") "aapt.exe"
$apksigner = Find-FirstFile (Join-Path $sdkRoot "build-tools") "apksigner.bat"
$adb = Find-FirstFile (Join-Path $sdkRoot "platform-tools") "adb.exe"
if (-not $aapt2 -or -not $aapt -or -not $apksigner -or -not $adb) { throw "The Android SDK installation is incomplete." }

# Persist the tool root for new terminals. The application also finds this default
# automatically, so no global PATH modification is needed.
[Environment]::SetEnvironmentVariable("SHADOWPATH_TOOLCHAIN_DIR", $toolRoot, "User")

Write-Host ""
Write-Host "Local static toolchain is ready:"
& $jadx.FullName --version
& $aapt2.FullName version
& $apksigner.FullName --help | Select-Object -First 1
& $adb.FullName version | Select-Object -First 1
Write-Host ""
Write-Host "Restart the SHADOWPATH API or run .\scripts\dev.ps1 to refresh the health page."
