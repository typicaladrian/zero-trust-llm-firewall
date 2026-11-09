"""PreToolUse hook for the Bash and PowerShell tools: guardrails permission rules can't express.

Permission rules match commands by their first word, so they miss a tool invoked by full
path, after `&&`, inside `bash -c '...'` or a `$(...)` substitution. This hook splits a
command into segments and words and decides per tool:

- deny: anything that would print secrets or credentials into the transcript
  (.env, Terraform state and tfvars, the local AWS credential folder, decrypted SSM
  parameters, Secrets Manager values, KMS decrypt, Terraform sensitive outputs, AWS
  calls that return credentials)
- ask:  owner-gated actions (docs/workflow.md): merging, releases and repo settings on
  GitHub; Terraform apply/destroy/import/test, state edits and state migration; AWS calls
  that aren't read-only; pushing container images
- allow: everything else, including read-only AWS and Terraform commands

Deny always wins over ask.

Known limitation (see docs/decisions/0012-agent-guardrails.md): a hook reads command
*text*. Code it can't see (a Python or boto3 script, a container running the AWS CLI, a
shell script on disk) isn't inspected. These guardrails are one layer of defense in depth,
not a sandbox; branch protection and the GitHub deploy approval are enforced server-side.
"""
import json
import re
import shlex
import sys

payload = json.load(sys.stdin)
original = payload.get("tool_input", {}).get("command", "")

# Line continuations (bash "\" and PowerShell "`" at line end) join lines into one command.
original = re.sub(r"[\\`]\r?\n", " ", original)

# Commit/PR/issue messages may mention guarded commands in prose, so blank out the quoted
# values of message flags. Exceptions: a double-quoted value containing $( or a backtick
# still runs that code in bash (and PowerShell), so it is kept and inspected.
MESSAGE_FLAG = r"((?:^|\s)(?:-m|--message|-t|--title|-b|--body)(?:\s+|=))"
QUOTED = r"(\"(?:\\.|[^\"\\])*\"|'[^']*')"


def blank_message(match):
    value = match.group(2)
    if value.startswith('"') and ("$(" in value or "`" in value):
        return match.group(0)
    return match.group(1) + '""'


command = re.sub(MESSAGE_FLAG + QUOTED, blank_message, original, flags=re.DOTALL)

DENY, ASK = "deny", "ask"
findings = []  # (decision, reason)
SEPARATORS = r"&&|\|\||[;|&\n]"

# ---------------------------------------------------------------------------
# Secret-bearing files, by path, whatever command touches them (globs included)
# ---------------------------------------------------------------------------
SECRET_PATHS = [
    (r"(?<![\w.-])\.env(?![\w.-])|[/\\]\.env(?![\w.-])",
     ".env holds live API keys and secrets. Use .env.example to see which settings exist."),
    (r"\.tf(?:st|var)",
     "Terraform state and tfvars can contain secrets in plain text. Use `terraform state list` or `terraform output` (sensitive values stay hidden)."),
    (r"(?:^|[\s/\\~'\"=])\.aws(?=$|[\s/\\'\"*])",
     "That's the local AWS credential folder. Use `aws sts get-caller-identity` to check who you're signed in as."),
]


def is_plain_check_ignore(segment):
    """`git check-ignore <paths>` never opens the files. Only that plain form is exempt."""
    return (re.match(r"\s*git\s+check-ignore\b", segment) is not None
            and not re.search(r"<|--stdin|\$\(|`", segment))


path_scan = "\n".join(seg for seg in re.split(SEPARATORS, command) if not is_plain_check_ignore(seg))
for pattern, reason in SECRET_PATHS:
    if re.search(pattern, path_scan):
        findings.append((DENY, reason))

compose_config = re.search(r"\bdocker[ -]compose\b.*\bconfig\b(.*)", command)
if compose_config and not re.search(r"\s(--quiet|-q|--services|--volumes|--profiles|--images|--hash)\b", compose_config.group(1)):
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
# AWS, Terraform and Docker: tokenize each segment and read the subcommand
# ---------------------------------------------------------------------------
TOOLS = {"aws", "terraform", "tofu", "docker", "docker-compose"}
AWS_GLOBAL_OPTIONS_WITH_VALUE = {
    "--region", "--profile", "--output", "--endpoint-url", "--query", "--color",
    "--cli-read-timeout", "--cli-connect-timeout", "--ca-bundle", "--cli-binary-format",
}
DOCKER_GLOBAL_OPTIONS_WITH_VALUE = {"--context", "-c", "--host", "-H", "--config", "--log-level", "-l"}
AWS_READ_PREFIXES = ("describe-", "list-", "get-", "head-", "batch-get-", "lookup-", "search-",
                     "filter-", "validate-", "estimate-", "wait")
AWS_READ_OPS = {"tail", "scan", "query", "help", ""}
AWS_CREDENTIAL_OP = re.compile(r"credential|password|token|access-key|^assume-role|^decrypt$|^generate-data-key")
INFRA_REASON = "This changes AWS infrastructure or ships an image, which the owner approves (docs/workflow.md, infrastructure gate)."


def clean(token):
    """Strip subshell syntax around a word: $(cmd ...), (cmd ...), `cmd ...`."""
    return token.lstrip("$(`").rstrip(")`")


def tool_calls(cmd, depth=0):
    """Yield (tool, args) for each aws / terraform / tofu / docker invocation, including ones
    nested in quoted strings such as `bash -c '...'` or `pwsh -Command "..."`."""
    for segment in re.split(SEPARATORS, cmd):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        tokens = [clean(t) for t in tokens]
        found = False
        for i, token in enumerate(tokens):
            if not found:
                name = re.split(r"[/\\]", token)[-1].lower()
                name = name[:-4] if name.endswith(".exe") else name
                if name in TOOLS:
                    found = True
                    yield name, tokens[i + 1:]
                    continue
            if depth < 2 and " " in token:  # a quoted command string: look inside it
                yield from tool_calls(token, depth + 1)


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


def flags(args):
    """Option names regardless of spelling: -json, --json and -json=true all become "json"."""
    return {a.lstrip("-").split("=")[0].lower() for a in args if a.startswith("-")}


def aws_decision(args):
    words = positional(args, AWS_GLOBAL_OPTIONS_WITH_VALUE)
    if not words:
        return None  # e.g. `aws --version`
    service, op = words[0], (words[1] if len(words) > 1 else "")
    if service in ("login", "logout", "help"):
        return None
    if op != "get-caller-identity" and AWS_CREDENTIAL_OP.search(op):
        return DENY, "This prints AWS credentials, a token or decrypted data into the transcript."
    if service == "configure":
        if op == "get" and re.search(r"secret|session_token|access_key", " ".join(args)):
            return DENY, "This prints stored AWS credentials."
        return None
    if service == "ssm" and op.startswith("get-parameter") and flags(args) & {"with-decryption", "cli-input-json", "cli-input-yaml"}:
        return DENY, "This can print decrypted secrets. Leave secrets in SSM; the app reads them at runtime."
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
    sub, opts = words[0], flags(args)
    if sub in ("apply", "destroy", "import", "taint", "untaint", "force-unlock", "refresh", "test"):
        return ASK, INFRA_REASON
    if sub == "console":
        return DENY, "`terraform console` can print sensitive values from state."
    if sub == "init" and opts & {"migrate-state", "force-copy", "reconfigure"}:
        return ASK, INFRA_REASON
    if sub == "workspace" and len(words) > 1 and words[1] == "delete":
        return ASK, INFRA_REASON
    if sub == "state":
        action = words[1] if len(words) > 1 else ""
        if action == "pull":
            return DENY, "`terraform state pull` prints the whole state, secrets included."
        if action in ("rm", "mv", "push", "replace-provider"):
            return ASK, INFRA_REASON
    if sub == "output" and opts & {"json", "raw"}:
        return DENY, "`terraform output -json/-raw` reveals sensitive outputs. Plain `terraform output` hides them."
    if sub == "show" and "json" in opts:
        return DENY, "`terraform show -json` reveals sensitive values."
    return None


def docker_decision(args, compose=False):
    words = positional(args, DOCKER_GLOBAL_OPTIONS_WITH_VALUE)
    if compose:
        words = ["compose"] + words
    joined = " ".join(args)
    pushes = (
        words[:1] == ["push"]
        or words[:2] in (["image", "push"], ["manifest", "push"], ["compose", "push"])
        or words[:3] == ["buildx", "imagetools", "create"]
        or ("--push" in args and words[:1] in (["build"], ["buildx"]))
        or re.search(r"type=registry|push=true", joined) is not None
    )
    return (ASK, INFRA_REASON) if pushes else None


for tool, args in tool_calls(command):
    if tool == "aws":
        result = aws_decision(args)
    elif tool in ("terraform", "tofu"):
        result = terraform_decision(args)
    else:
        result = docker_decision(args, compose=(tool == "docker-compose"))
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
