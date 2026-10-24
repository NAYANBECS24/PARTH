[CmdletBinding()]
param(
  [string]$Python = "C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe",
  [ValidateRange(1024, 65535)][int]$ApiPort = 8000,
  [ValidateRange(1024, 65535)][int]$WebPort = 5173,
  [switch]$SkipDependencyInstall
)

function Assert-LocalPortAvailable {
  param([int]$Port, [string]$ServiceName)

  # A direct connect is more reliable than Get-NetTCPConnection on machines where
  # the CIM provider misses a live loopback listener. We still use CIM only to
  # enrich the error with an owner PID when it is available.
  $client = [System.Net.Sockets.TcpClient]::new()
  $occupied = $false
  try {
    $connection = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
    if ($connection.AsyncWaitHandle.WaitOne(400)) {
      $client.EndConnect($connection)
      $occupied = $true
    }
  }
  catch [System.Net.Sockets.SocketException] {
    $occupied = $false
  }
  finally {
    $client.Dispose()
  }

  if ($occupied) {
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    $process = if ($listener) { Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue } else { $null }
    $owner = if ($process) { "$($process.ProcessName) (PID $($process.Id))" } elseif ($listener) { "PID $($listener.OwningProcess)" } else { "another local process" }
    throw "$ServiceName cannot start because port $Port is already in use by $owner. Stop that process or rerun with a different port."
  }
}

function Stop-ManagedProcess {
  param($Process, [string]$Name)

  if ($null -ne $Process -and -not $Process.HasExited) {
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    Write-Host "Stopped $Name process $($Process.Id)."
  }
}

$startingLocation = Get-Location
try {
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "Created .env from .env.example"
}
if (-not (Test-Path $Python)) {
  throw "Python 3.12 was not found at '$Python'. Pass -Python <path-to-python.exe>."
}

if (-not $SkipDependencyInstall) {
  & $Python -m pip install -r backend/requirements.txt
  if ($LASTEXITCODE -ne 0) { throw "Backend dependency install failed." }
}
& $Python -c "from backend.database import initialise_database; initialise_database(); print('Database initialised.')"
if ($LASTEXITCODE -ne 0) { throw "Database initialisation failed." }

Push-Location frontend
if (-not $SkipDependencyInstall -and -not (Test-Path "node_modules")) { npm install }
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Frontend dependency install failed." }
Pop-Location

# Recheck immediately before starting children: dependency installation can take a
# while, during which another local service may have claimed a default port.
Assert-LocalPortAvailable -Port $ApiPort -ServiceName "API"
Assert-LocalPortAvailable -Port $WebPort -ServiceName "Web UI"
$env:SHADOWPATH_CORS_ORIGINS = "http://127.0.0.1:$WebPort,http://localhost:$WebPort"

$api = $null
$worker = $null
try {
  $api = Start-Process -FilePath $Python -ArgumentList "-m", "uvicorn", "backend.api:app", "--host", "127.0.0.1", "--port", "$ApiPort" -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
  $worker = Start-Process -FilePath $Python -ArgumentList "-m", "backend.worker" -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
  Write-Host "API process $($api.Id), worker process $($worker.Id)."
  Write-Host "Opening Vite at http://127.0.0.1:$WebPort. Press Ctrl+C to stop all project processes."
  Set-Location (Join-Path $projectRoot "frontend")
  npm run dev -- --host 127.0.0.1 --port $WebPort
  if ($LASTEXITCODE -ne 0) { throw "Vite exited with code $LASTEXITCODE." }
}
finally {
  Stop-ManagedProcess -Process $worker -Name "worker"
  Stop-ManagedProcess -Process $api -Name "API"
}
}
finally {
  Set-Location -LiteralPath $startingLocation.Path
}
