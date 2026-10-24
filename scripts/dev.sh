#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -m pip install -r backend/requirements.txt
"$PYTHON_BIN" -c 'from backend.database import initialise_database; initialise_database(); print("Database initialised.")'

if [[ ! -d frontend/node_modules ]]; then
  (cd frontend && npm install)
fi

"$PYTHON_BIN" -m uvicorn backend.api:app --host 127.0.0.1 --port 8000 &
API_PID=$!
"$PYTHON_BIN" -m backend.worker &
WORKER_PID=$!
trap 'kill "$API_PID" "$WORKER_PID" 2>/dev/null || true' EXIT
(cd frontend && npm run dev)
