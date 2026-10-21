"""The PreToolUse hook that guards agent shell commands (.claude/hooks/guard_bash.py).

Protects non-negotiable #2 (never expose .env) and the owner's merge gate
(docs/workflow.md, Gate 2) against agents, however they spell the command.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / ".claude" / "hooks" / "guard_bash.py"
DOT = "." + "env"
GH = '"C:\\Program Files\\GitHub CLI\\gh.exe"'


def decision(command: str) -> str:
    out = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}),
        capture_output=True, text=True, check=True,
    ).stdout
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out.strip() else "allow"


@pytest.mark.parametrize("command", [
    f"cat {DOT}",
    f"grep ANTHROPIC {DOT}",
    f"source ./{DOT}",
    f"type C:\\repo\\{DOT}",
    f"git add -f {DOT}",
    "docker compose config",
    f'git commit -m "msg" && cat {DOT}',
    f"{GH} pr create --body x; type {DOT}",
])
def test_secret_access_is_denied(command):
    assert decision(command) == "deny"


@pytest.mark.parametrize("command", [
    "gh pr merge 12 --merge",
    f"{GH} pr merge 12 --merge",
    "/c/Program\\ Files/GitHub\\ CLI/gh.exe pr merge 3",
    "gh release create v1.0.0",
    f"{GH} repo edit --visibility private",
    "gh api -X PUT repos/o/r/branches/main/protection",
    "gh api --method DELETE repos/o/r",
])
def test_owner_gated_github_actions_ask_the_owner(command):
    assert decision(command) == "ask"


@pytest.mark.parametrize("command", [
    f"cat {DOT}.example",
    "docker compose config --quiet",
    f'git commit -q -m "Chore: guard {DOT} reads\n\n- block {DOT} access"',
    "git commit -m 'Docs: explain the gh pr merge policy'",
    f"{GH} pr create --title t --body 'mentions {DOT}; merge with gh pr merge'",
    f"{GH} issue comment 4 --body-file plan.md",
    f"{GH} issue view 4 --json title,body,comments",
    "gh pr checks 12",
    "gh release list",
    "gh api repos/o/r/pulls",
])
def test_everyday_commands_are_allowed(command):
    assert decision(command) == "allow"
