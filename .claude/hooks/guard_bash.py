"""PreToolUse hook for Bash: enforces the guardrails that permission rules can't express.

1. Denies shell access to .env (cat .env, grep KEY .env, source .env, docker compose
   config, ...). Permission rules already block the Read/Edit tools; this closes the
   shell route. .env.example is always allowed.
2. Asks the owner before owner-gated GitHub actions (merging, releases, repo settings,
   mutating API calls). Permission rules only match commands that start with `gh`,
   so this also catches gh invoked by full path, e.g. "C:\\Program Files\\GitHub CLI\\gh.exe".
"""
import json
import re
import sys

payload = json.load(sys.stdin)
original = payload.get("tool_input", {}).get("command", "")

# `gh`, `gh.exe`, or a full path ending in either, optionally followed by a closing quote
GH = r"(?<![\w-])gh(?:\.exe)?[\"']?\s+"

OWNER_GATED = [
    (GH + r"pr\s+merge\b", "merging a pull request"),
    (GH + r"release\s+(create|delete|edit|upload)\b", "changing a release"),
    (GH + r"repo\s+(edit|delete|rename|archive)\b", "changing repository settings"),
    (GH + r"api\b.*(-X|--method)\s*=?\s*[\"']?(PUT|PATCH|DELETE|POST)\b", "a mutating GitHub API call"),
]

# Commit/PR/issue messages may mention .env or `gh pr merge` in prose. Blank out the
# quoted values of message flags only, so `git commit -m "x" && cat .env` is still caught.
MESSAGE_FLAG = r"((?:^|\s)(?:-m|--message|-t|--title|-b|--body)(?:\s+|=))"
QUOTED = r"(\"(?:\\.|[^\"\\])*\"|'[^']*')"
command = re.sub(MESSAGE_FLAG + QUOTED, r'\1""', original, flags=re.DOTALL)

decision, reason = None, None
# ".env" as a whole path component, but not ".env.example" / ".envrc" / "venv"
if re.search(r"(?<![\w.-])\.env(?![\w.-])", command) or re.search(r"[/\\]\.env(?![\w.-])", command):
    decision, reason = "deny", ".env holds live API keys and secrets. Use .env.example to see which settings exist."
# `docker compose config` prints the merged config with .env values filled in
elif re.search(r"\bdocker[ -]compose\b.*\bconfig\b", command) and not re.search(r"\s(--quiet|-q)\b", command):
    decision, reason = "deny", "`docker compose config` prints secrets from .env. Use `docker compose config --quiet` to validate."
else:
    for pattern, action in OWNER_GATED:
        if re.search(pattern, command, flags=re.IGNORECASE):
            decision, reason = "ask", f"This is {action}, which the owner approves (docs/workflow.md, Gate 2)."
            break

if decision:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
sys.exit(0)
