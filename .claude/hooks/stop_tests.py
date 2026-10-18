"""Stop hook: Claude can't end its turn with a failing fast test tier.

Runs `pytest` only when Python files differ from origin/main (committed or not),
and skips the run if this exact code state already passed. On failure it blocks
the stop and hands the failure summary back to Claude to fix.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])
STATE_FILE = ROOT / ".claude" / "hooks" / ".last-green"


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout


payload = json.load(sys.stdin)
if payload.get("stop_hook_active"):
    sys.exit(0)  # already continuing because of this hook; don't loop forever

changed_py = [
    f for f in (git("diff", "--name-only", "origin/main") + git("ls-files", "--others", "--exclude-standard")).split()
    if f.endswith(".py")
]
if not changed_py:
    sys.exit(0)

state = hashlib.sha256()
state.update(git("rev-parse", "HEAD").encode())
state.update(git("diff", "HEAD", "--", "*.py").encode())
for f in sorted(changed_py):
    path = ROOT / f
    if path.exists():
        state.update(path.read_bytes())
fingerprint = state.hexdigest()

if STATE_FILE.exists() and STATE_FILE.read_text().strip() == fingerprint:
    sys.exit(0)

result = subprocess.run(
    [sys.executable, "-m", "pytest", "-q", "-p", "no:warnings", "--no-header"],
    cwd=ROOT, capture_output=True, text=True,
)
if result.returncode == 0:
    STATE_FILE.write_text(fingerprint)
    sys.exit(0)

tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-25:])
print(json.dumps({
    "decision": "block",
    "reason": f"The fast test tier fails on your changes. Fix it before finishing (CLAUDE.md non-negotiable #5/#6):\n{tail}",
}))
sys.exit(0)
