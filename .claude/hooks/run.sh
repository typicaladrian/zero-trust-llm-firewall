#!/usr/bin/env bash
# Runs a hook script with the project's Python (venv first, then system Python).
# Usage: run.sh <script.py>   (hook input JSON arrives on stdin and is passed through)
set -u
ROOT="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
for py in "$ROOT/venv/Scripts/python.exe" "$ROOT/venv/bin/python" python3 python; do
  if command -v "$py" >/dev/null 2>&1 || [ -x "$py" ]; then
    exec "$py" "$ROOT/.claude/hooks/$1"
  fi
done
echo "No Python interpreter found for hook $1" >&2
exit 1
