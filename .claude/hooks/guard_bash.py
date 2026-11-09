"""PreToolUse hook for Bash: enforces the guardrails that permission rules can't express.

Permission rules match commands by their first word, so they miss a tool invoked by full
path (e.g. "C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe") or a gated step after `&&`.
This hook splits each command into its parts and decides per tool:

- deny: anything that would print secrets or credentials into the transcript
  (.env, Terraform state and tfvars, local AWS credential caches, decrypted SSM
  parameters, Secrets Manager values, Terraform sensitive outputs, AWS credential calls)
- ask:  owner-gated actions (docs/workflow.md): merging, releases and repo settings on
  GitHub; Terraform apply/destroy/import and state surgery; AWS calls that change
  something; pushing container images
- allow: everything else, including read-only AWS and Terraform commands

Deny always wins over ask.
"""
import json
import re
import shlex
import sys

payload = json.load(sys.stdin)
original = payload.get("tool_input", {}).get("command", "")

# Commit/PR/issue messages may mention these commands in prose. Blank out the quoted values
# of message flags only, so `git commit -m "x" && cat .env` is still caught.
MESSAGE_FLAG = r"((?:^|\s)(?:-m|--message|-t|--title|-b|--body)(?:\s+|=))"
QUOTED = r"(\"(?:\\.|[^\"\\])*\"|'[^']*')"
command = re.sub(MESSAGE_FLAG + QUOTED, r'\1""', original, flags=re.DOTALL)

DENY, ASK = "deny", "ask"
findings = []  # (decision, reason)

# ---------------------------------------------------------------------------
# Secret-bearing files, by path, whatever command touches them
# ---------------------------------------------------------------------------
SECRET_PATHS = [
    (r"(?<![\w.-])\.env(?![\w.-])|[/\\]\.env(?![\w.-])",
     ".env holds live API keys and secrets. Use .env.example to see which settings exist."),
    (r"\.tfstate\b",
     "Terraform state can contain secrets in plain text. Use `terraform state list` or `terraform output` (sensitive values stay hidden)."),
    (r"\.tfvars\b",
     "tfvars files can hold secrets. Pass non-secret values another way, or ask the owner."),
    (r"\.aws[/\\](?:credentials|login|sso|cli)\b",
     "That's the local AWS credential cache. Use `aws sts get-caller-identity` to check who you're signed in as."),
]
# `git check-ignore` only asks git whether a path would be ignored; it never opens the file.
# It's the one command allowed to name secret-bearing paths (used to verify .gitignore).
path_scan = "\n".join(seg for seg in re.split(r"&&|\|\||[;|\n]", command)
                      if not re.match(r"\s*git\s+check-ignore\b", seg))
for pattern, reason in SECRET_PATHS:
    if re.search(pattern, path_scan):
        findings.append((DENY, reason))

if re.search(r"\bdocker[ -]compose\b.*\bconfig\b", command) and not re.search(r"\s(--quiet|-q)\b", command):
    findings.append((DENY, "`docker compose config` prints secrets from .env. Use `docker compose config --quiet` to validate."))

# ---------------------------------------------------------------------------
# GitHub CLI (regex: gh's own subcommands are simple)
# ---------------------------------------------------------------------------
GH = r"(?<![\w-])gh(?:\.exe)?[\"']?\s+"
GH_GATED = [
    (GH + r"pr\s+merge\b", "merging a pull request"),
    (GH + r"release\s+(create|delete|edit|upload)\b", "changing a release"),
    (GH + r"repo\s+(edit|delete|rename|archive)\b", "changing repository settings"),
    (GH + r"api\b.*(-X|--method)\s*=?\s*[\"']?(PUT|PATCH|DELETE|POST)\b", "a mutating GitHub API call"),
]
for pattern, action in GH_GATED:
    if re.search(pattern, command, flags=re.IGNORECASE):
        findings.append((ASK, f"This is {action}, which the owner approves (docs/workflow.md, Gate 2)."))
        break

# ---------------------------------------------------------------------------
# AWS, Terraform and Docker: tokenize each command segment and read the subcommand
# ---------------------------------------------------------------------------
AWS_GLOBAL_OPTIONS_WITH_VALUE = {
    "--region", "--profile", "--output", "--endpoint-url", "--query", "--color",
    "--cli-read-timeout", "--cli-connect-timeout", "--ca-bundle", "--cli-binary-format",
}
AWS_READ_PREFIXES = ("describe-", "list-", "get-", "head-", "batch-get-", "lookup-", "search-",
                     "filter-", "validate-", "estimate-", "wait")
AWS_READ_OPS = {"tail", "scan", "query", "help", ""}
AWS_CREDENTIAL_OPS = {"get-session-token", "get-federation-token", "get-login-password",
                      "get-authorization-token", "assume-role", "assume-role-with-web-identity",
                      "assume-role-with-saml", "export-credentials"}
INFRA_REASON = "This changes AWS infrastructure or ships an image, which the owner approves (docs/workflow.md, infrastructure gate)."


def tool_calls(cmd):
    """Yield (tool, args) for each aws / terraform / tofu / docker invocation in the command."""
    for segment in re.split(r"&&|\|\||[;|\n]", cmd):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        for i, token in enumerate(tokens):
            name = re.split(r"[/\\]", token)[-1].lower()
            name = name[:-4] if name.endswith(".exe") else name
            if name in ("aws", "terraform", "tofu", "docker"):
                yield name, tokens[i + 1:]
                break


def positional(args, options_with_value=()):
    """Arguments that aren't options (or values of options listed as taking one)."""
    words, skip = [], False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = "=" not in arg and arg in options_with_value
            continue
        words.append(arg)
    return words


def aws_decision(args):
    words = positional(args, AWS_GLOBAL_OPTIONS_WITH_VALUE)
    if not words:
        return None  # e.g. `aws --version`
    service, op = words[0], (words[1] if len(words) > 1 else "")
    if service in ("login", "logout", "help"):
        return None
    if op in AWS_CREDENTIAL_OPS:
        return DENY, "This prints AWS credentials or a login token into the transcript."
    if service == "configure":
        if op == "get" and re.search(r"secret|session_token|access_key", " ".join(args)):
            return DENY, "This prints stored AWS credentials."
        return None
    if service == "ssm" and op.startswith("get-parameter") and "--with-decryption" in args:
        return DENY, "This prints decrypted secrets. Leave secrets in SSM; the app reads them at runtime."
    if service == "secretsmanager" and op in ("get-secret-value", "batch-get-secret-value"):
        return DENY, "This prints a secret value."
    if service == "s3":
        return None if op == "ls" else (ASK, INFRA_REASON)
    if op in AWS_READ_OPS or op.startswith(AWS_READ_PREFIXES):
        return None
    return ASK, INFRA_REASON


def terraform_decision(args):
    words = positional(args)
    if not words:
        return None
    sub = words[0]
    if sub in ("apply", "destroy", "import", "taint", "untaint", "force-unlock", "refresh"):
        return ASK, INFRA_REASON
    if sub == "console":
        return DENY, "`terraform console` can print sensitive values from state."
    if sub == "state":
        action = words[1] if len(words) > 1 else ""
        if action == "pull":
            return DENY, "`terraform state pull` prints the whole state, secrets included."
        if action in ("rm", "mv", "push", "replace-provider"):
            return ASK, INFRA_REASON
    if sub == "output" and any(a in ("-json", "-raw") for a in args):
        return DENY, "`terraform output -json/-raw` reveals sensitive outputs. Plain `terraform output` hides them."
    if sub == "show" and "-json" in args:
        return DENY, "`terraform show -json` reveals sensitive values."
    return None


def docker_decision(args):
    words = positional(args)
    if words[:1] == ["push"] or words[:2] == ["image", "push"]:
        return ASK, INFRA_REASON
    if words[:1] in (["build"], ["buildx"]) and "--push" in args:
        return ASK, INFRA_REASON
    return None


for tool, args in tool_calls(command):
    decide = {"aws": aws_decision, "terraform": terraform_decision,
              "tofu": terraform_decision, "docker": docker_decision}[tool]
    result = decide(args)
    if result:
        findings.append(result)

# ---------------------------------------------------------------------------
if findings:
    decision = DENY if any(d == DENY for d, _ in findings) else ASK
    reason = next(r for d, r in findings if d == decision)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
sys.exit(0)
