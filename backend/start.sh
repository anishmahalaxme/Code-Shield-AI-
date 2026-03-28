#!/usr/bin/env bash
# CodeShield Backend — start script
# Always uses the project .venv to ensure all dependencies (groq, dotenv) are available
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

# Install deps if venv is missing
if [ ! -f "$VENV/bin/uvicorn" ]; then
  echo "[start.sh] .venv not found or incomplete — running pip install..."
  "$VENV/bin/python" -m pip install -r "$SCRIPT_DIR/requirements.txt" -q
fi

echo "[start.sh] Starting CodeShield backend using .venv Python..."
cd "$SCRIPT_DIR"
exec "$VENV/bin/uvicorn" app.main:app --reload --host 0.0.0.0 --port 8000
