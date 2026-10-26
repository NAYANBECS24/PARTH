[CmdletBinding()]
param(
  [ValidateRange(1024, 65535)][int]$ApiPort = 8000,
  [ValidateRange(1024, 65535)][int]$WebPort = 5173,
  [ValidateRange(1024, 65535)][int]$MobsfPort = 8001
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = "C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $python)) { $python = "py" }

function Assert-PortFree {
  param([int]$Port)
  if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is already in use. Stop the existing service, then retry."
  }
}

function Stop-HostProcess {
  param($Process)
  if ($Process -and -not $Process.HasExited) {
    Stop-ChildProcesses -ParentId $Process.Id
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
  }
}

function Stop-ChildProcesses {
  param([int]$ParentId)
  $children = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ParentProcessId -eq $ParentId })
  foreach ($child in $children) {
    Stop-ChildProcesses -ParentId $child.ProcessId
    Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
  }
}

$cloudflared = (Get-Command cloudflared -ErrorAction SilentlyContinue).Source
if (-not $cloudflared) {
  $bundledCloudflared = Join-Path $projectRoot ".toolcache\bin\cloudflared.exe"
  if (Test-Path $bundledCloudflared) { $cloudflared = $bundledCloudflared }
}
if (-not $cloudflared) {
  throw "cloudflared is not installed. Install it with: winget install --id Cloudflare.cloudflared --exact"
}

Assert-PortFree $ApiPort
Assert-PortFree $WebPort
Set-Location $projectRoot

# configure-mobsf.ps1 writes this ignored file. Keeping the key outside the
# repository lets the API and worker use only the loopback-isolated service.
$mobsfConfig = Join-Path $projectRoot ".mobsf.env"
if (Test-Path $mobsfConfig) {
  $mobsfKeyLine = Get-Content -LiteralPath $mobsfConfig | Where-Object { $_ -match '^MOBSF_API_KEY=' } | Select-Object -First 1
  if ($mobsfKeyLine) {
    $env:MOBSF_API_KEY = $mobsfKeyLine.Substring("MOBSF_API_KEY=".Length).Trim()
    $env:MOBSF_API_URL = "http://127.0.0.1:$MobsfPort"
  }
}

$tunnelLog = Join-Path $env:TEMP "shadowpath-cloudflared-$([guid]::NewGuid().ToString('N')).log"
$tunnelError = "$tunnelLog.err"
$api = $null
$worker = $null
$web = $null
$tunnel = $null

try {
  $api = Start-Process -FilePath $python -ArgumentList "-m", "uvicorn", "backend.api:app", "--host", "127.0.0.1", "--port", "$ApiPort" -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
  $worker = Start-Process -FilePath $python -ArgumentList "-m", "backend.worker" -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
  $webCommand = "set VITE_USE_PROXY=true&& npm run dev -- --host 127.0.0.1 --port $WebPort"
  $web = Start-Process -FilePath "cmd.exe" -ArgumentList "/d", "/c", $webCommand -WorkingDirectory (Join-Path $projectRoot "frontend") -WindowStyle Hidden -PassThru

  $ready = $false
  foreach ($attempt in 1..40) {
    try {
      Invoke-WebRequest "http://127.0.0.1:$ApiPort/health" -UseBasicParsing -ErrorAction Stop | Out-Null
      Invoke-WebRequest "http://127.0.0.1:$WebPort" -UseBasicParsing -ErrorAction Stop | Out-Null
      $ready = $true
      break
    }
    catch { Start-Sleep -Milliseconds 500 }
  }
  if (-not $ready) { throw "The local API or web server did not become ready." }

  # HTTP/2 avoids UDP/QUIC blocks that are common on school, office, and mobile networks.
  $tunnel = Start-Process -FilePath $cloudflared -ArgumentList "--protocol", "http2", "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:$WebPort" -RedirectStandardOutput $tunnelLog -RedirectStandardError $tunnelError -WindowStyle Hidden -PassThru
  $publicUrl = $null
  foreach ($attempt in 1..80) {
    $lines = @(Get-Content -LiteralPath $tunnelLog -ErrorAction SilentlyContinue) + @(Get-Content -LiteralPath $tunnelError -ErrorAction SilentlyContinue)
    $match = $lines | Select-String -Pattern 'https://[-a-z0-9]+\.trycloudflare\.com' | Select-Object -First 1
    if ($match) {
      $publicUrl = $match.Matches[0].Value
      break
    }
    if ($tunnel.HasExited) { throw "Cloudflare Tunnel stopped before providing a public URL." }
    Start-Sleep -Milliseconds 500
  }
  if (-not $publicUrl) { throw "Cloudflare Tunnel did not provide a public URL within 40 seconds." }

  Write-Host ""
  Write-Host "SHADOWPATH full toolchain is public at: $publicUrl"
  Write-Host "Keep this window running. Press Ctrl+C to stop the tunnel, API, worker, and web server."
  while (-not $tunnel.HasExited) { Start-Sleep -Seconds 2 }
}
finally {
  Stop-HostProcess $tunnel
  Stop-HostProcess $web
  Stop-HostProcess $worker
  Stop-HostProcess $api
}
