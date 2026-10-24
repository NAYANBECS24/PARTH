[CmdletBinding()]
param(
  [string]$Python = "C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe"
)

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "Created .env from .env.example"
}
if (-not (Test-Path $Python)) {
  throw "Python 3.12 was not found at '$Python'. Pass -Python <path-to-python.exe>."
}
foreach ($port in 8000, 5173) {
  if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $port is already in use. Stop the existing process or choose a different local setup."
  }
}

& $Python -m pip install -r backend/requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Backend dependency install failed." }
& $Python -c "from backend.database import initialise_database; initialise_database(); print('Database initialised.')"
if ($LASTEXITCODE -ne 0) { throw "Database initialisation failed." }

Push-Location frontend
if (-not (Test-Path "node_modules")) { npm install }
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "Frontend dependency install failed." }
Pop-Location

$api = Start-Process -FilePath $Python -ArgumentList "-m", "uvicorn", "backend.api:app", "--host", "127.0.0.1", "--port", "8000" -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
$worker = Start-Process -FilePath $Python -ArgumentList "-m", "backend.worker" -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
Write-Host "API process $($api.Id), worker process $($worker.Id)."
Write-Host "Opening Vite at http://127.0.0.1:5173. Stop it with Ctrl+C; API/worker remain separate processes."
Set-Location (Join-Path $projectRoot "frontend")
npm run dev
