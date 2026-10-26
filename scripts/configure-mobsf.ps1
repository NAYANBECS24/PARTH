[CmdletBinding()]
param(
  [ValidateRange(1024, 65535)][int]$Port = 8001
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $projectRoot ".mobsf.env"
$containerName = "shadowpath-mobsf"
$volumeName = "shadowpath_mobsf_data"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker Desktop is required to run the isolated MobSF container."
}

if (-not (Test-Path $configPath)) {
  $keyBytes = New-Object byte[] 32
  $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $random.GetBytes($keyBytes)
  $random.Dispose()
  $apiKey = -join ($keyBytes | ForEach-Object { $_.ToString("x2") })
  [System.IO.File]::WriteAllText(
    $configPath,
    "MOBSF_API_KEY=$apiKey$([Environment]::NewLine)",
    [System.Text.UTF8Encoding]::new($false)
  )
}

$configLines = @(Get-Content -LiteralPath $configPath)
if (-not ($configLines | Where-Object { $_ -match '^MOBSF_API_URL=' })) {
  [System.IO.File]::AppendAllText(
    $configPath,
    "MOBSF_API_URL=http://127.0.0.1:$Port$([Environment]::NewLine)",
    [System.Text.UTF8Encoding]::new($false)
  )
}

# Named Docker volumes are initially root-owned. MobSF runs as UID 9901, so
# prepare the persistent data volume before launching its unprivileged process.
& docker volume create $volumeName | Out-Null
& docker run --rm --user root --entrypoint /bin/bash `
  --volume "${volumeName}:/data" `
  opensecurity/mobile-security-framework-mobsf:latest `
  -lc "mkdir -p /data && chown -R 9901:9901 /data" | Out-Null

$existing = (@(& docker ps -aq --filter "name=^/$containerName$") -join "").Trim()
if ($existing) {
  $running = (@(& docker inspect -f '{{.State.Running}}' $containerName) -join "").Trim()
  if ($running -ne "true") { & docker start $containerName | Out-Null }
}
else {
  & docker run --detach --name $containerName --restart unless-stopped `
    --publish "127.0.0.1:${Port}:8000" `
    --env-file $configPath `
    --volume "${volumeName}:/home/mobsf/.MobSF" `
    opensecurity/mobile-security-framework-mobsf:latest | Out-Null
}

$ready = $false
foreach ($attempt in 1..90) {
  try {
    $response = Invoke-WebRequest "http://127.0.0.1:$Port" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
      $ready = $true
      break
    }
  }
  catch { Start-Sleep -Seconds 2 }
}
if (-not $ready) {
  throw "MobSF did not become ready. Inspect it with: docker logs $containerName"
}

Write-Host "MobSF static analyzer is ready at http://127.0.0.1:$Port"
Write-Host "Its API key is stored only in the ignored .mobsf.env file."
Write-Host "Run .\scripts\host-free.ps1 again to include MobSF in the hosted API and worker."
