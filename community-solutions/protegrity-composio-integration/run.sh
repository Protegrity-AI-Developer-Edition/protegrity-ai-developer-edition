#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run.sh — Start the Protegrity × Composio Secure Data Bridge demo
# ─────────────────────────────────────────────────────────────────────────────
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env if present
if [ -f .env ]; then
  set -o allexport; source .env; set +o allexport
  echo "✓ Loaded .env"
fi

PORT="${PORT:-8900}"

# Use the venv python if available
PYTHON="${PYTHON_BIN:-/home/azure_usr/myenv/bin/python}"
if [ ! -f "$PYTHON" ]; then
  PYTHON="$(which python3)"
fi

echo ""
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║   Protegrity × Composio — Secure Data Bridge             ║"
echo "  ║   http://localhost:${PORT}                                    ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "  Prerequisites:"
echo "  1. Run 'docker compose up -d' in the protegrity-developer-edition folder"
echo "  2. Connect at least one Composio app via the UI or 'composio connected-accounts'"
echo ""

exec "$PYTHON" -m uvicorn main:app --host 0.0.0.0 --port "$PORT" --reload
