#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if grep -q '^SHADOWPATH_ENABLE_NVIDIA=true$' .env && [[ -z "${NVIDIA_API_KEY:-}" ]]; then
  read -r -s -p "NVIDIA API key (input hidden; retained only for this run): " NVIDIA_API_KEY
  echo
  export NVIDIA_API_KEY
  if [[ -z "$NVIDIA_API_KEY" ]]; then
    echo "NVIDIA was enabled but no API key was entered." >&2
    exit 1
  fi
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
