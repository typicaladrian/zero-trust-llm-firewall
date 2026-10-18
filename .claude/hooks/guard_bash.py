"""PreToolUse hook for Bash: stops shell commands from exposing secrets in .env.

Permission rules already block the Read/Edit tools on .env; this closes the shell
route (cat .env, grep KEY .env, source .env, docker compose config, ...).
.env.example is always allowed.
"""
import json
import re
import sys

payload = json.load(sys.stdin)
command = payload.get("tool_input", {}).get("command", "")

# Commit/PR/issue messages may mention .env in prose. For those commands, ignore
# quoted text (the message) but still check the rest, e.g. `git commit -m "x" && cat .env`.
if re.search(r"\b(git\s+commit|gh\s+(pr|issue)\s+(create|edit|comment))\b", command):
    command = re.sub(r'"(?:\\.|[^"\\])*"' + r"|'[^']*'", '""', command, flags=re.DOTALL)

reason = None
# ".env" as a whole path component, but not ".env.example" / ".envrc" / "venv"
if re.search(r"(?<![\w.-])\.env(?![\w.-])", command) or re.search(r"[/\\]\.env(?![\w.-])", command):
    reason = ".env holds live API keys and secrets. Use .env.example to see which settings exist."
# `docker compose config` prints the merged config with .env values filled in
elif re.search(r"\bdocker[ -]compose\b.*\bconfig\b", command) and not re.search(r"\s(--quiet|-q)\b", command):
    reason = "`docker compose config` prints secrets from .env. Use `docker compose config --quiet` to validate."

if reason:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
sys.exit(0)
