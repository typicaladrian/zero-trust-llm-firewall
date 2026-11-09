"""PreToolUse hook for the Bash and PowerShell tools: guardrails permission rules can't express.

Permission rules match commands by their first word, so they miss a tool invoked by full
path, after `&&`, inside `bash -c '...'` or a `$(...)` substitution. This hook tokenizes the
command the way a shell would (quoted strings stay whole, operators become separators),
looks inside quoted command strings and substitutions, and decides per tool:

- deny: anything that would print secrets or credentials into the transcript
  (.env, Terraform state and tfvars, the local AWS credential folder, decrypted SSM
  parameters, Secrets Manager values, KMS decrypt, Terraform sensitive outputs, AWS
  calls that return credentials)
- ask:  owner-gated actions (docs/workflow.md): merging, releases and repo settings on
  GitHub; Terraform apply/destroy/import/test, state edits and state migration; AWS calls
  that aren't read-only; pushing container images
- allow: everything else, including read-only AWS and Terraform commands

Deny always wins over ask.

Known limitation (docs/decisions/0012-agent-guardrails.md): a hook reads command *text*.
It can't see code it can't read (a Python or boto3 script, a script on disk, a container
running the AWS CLI) or shell tricks that build commands at run time (variables, ${IFS},
brace expansion). It is one layer of defense in depth, not a sandbox; branch protection
and the GitHub deploy approval are enforced server-side.
"""
import json
import re
import shlex
import sys

payload = json.load(sys.stdin)
command = payload.get("tool_input", {}).get("command", "")

# Line continuations (bash "\" and PowerShell "`" at line end) join lines into one command.
command = re.sub(r"[\\`]\r?\n", " ", command)
# `--message="x y"` -> `--message "x y"`, so the quoted value stays one token.
command = re.sub(r"(\s--(?:message|title|body))=", r"\1 ", command)

DENY, ASK = "deny", "ask"
OPERATOR_CHARS = "();<>|&\n"
MESSAGE_FLAGS = {"-m", "--message", "-t", "--title", "-b", "--body"}
# A heredoc whose delimiter is quoted (<<'EOF') is literal text: nothing in it runs.
LITERAL_HEREDOC = re.compile(r"^\$\(cat <<-?'(\w+)'\n.*\n\1\s*\)$", re.DOTALL)

findings = []  # (decision, reason)


# ---------------------------------------------------------------------------
# Tokenizing and segmenting
# ---------------------------------------------------------------------------
def tokenize(text):
    """Shell-like words: quotes kept (and kept whole), operators as separate tokens."""
    lexer = shlex.shlex(text, posix=False, punctuation_chars=OPERATOR_CHARS)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes: fall back to whitespace
        return text.split()


def unquote(token):
    if len(token) >= 2 and token[0] in "'\"" and token[-1] == token[0]:
        return token[1:-1]
    return token


def word(token):
    """A token as a plain word: no quotes, no leftover subshell characters."""
    return unquote(token).strip("`").lstrip("$")


def basename(token):
    name = re.split(r"[/\\]", word(token))[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def is_quoted(token):
    return len(token) >= 2 and token[0] in "'\"" and token[-1] == token[0]


def runs_code(token):
    """A double-quoted string containing $( or a backtick executes it (bash and PowerShell)."""
    return token.startswith('"') and ("$(" in token or "`" in token) and not LITERAL_HEREDOC.match(unquote(token))


def segments(text, depth=0):
    """Yield each simple command as a list of tokens, with message values replaced by '""',
    including commands nested in quoted strings (bash -c '...') and substitutions."""
    current = []
    for token in tokenize(text) + [";"]:
        if token and all(c in OPERATOR_CHARS for c in token):
            if current:
                yield from finish(current, depth)
                current = []
        else:
            current.append(token)


def finish(tokens, depth):
    is_vcs = basename(tokens[0]) in ("git", "gh") if tokens else False
    out, nested, i = [], [], 0
    while i < len(tokens):
        token = tokens[i]
        out.append(token)
        if is_vcs and token in MESSAGE_FLAGS and i + 1 < len(tokens):
            value = tokens[i + 1]
            if runs_code(value):
                nested.append(unquote(value))
                out.append(value)
            else:
                out.append('""')  # a message is text, not a command
            i += 2
            continue
        if depth < 3 and is_quoted(token) and re.search(r"\s", token):
            nested.append(unquote(token))  # e.g. bash -c "cd infra && terraform apply"
        i += 1
    yield out
    for inner in nested:
        yield from segments(inner, depth + 1)


ALL_SEGMENTS = list(segments(command))

# ---------------------------------------------------------------------------
# Secret-bearing files, by path (globs included), in every segment
# ---------------------------------------------------------------------------
SECRET_PATHS = [
    (r"(?<![\w.-])\.env(?![\w.-])|[/\\]\.env(?![\w.-])",
     ".env holds live API keys and secrets. Use .env.example to see which settings exist."),
    (r"\.tfst(?:ate|[*?\[])|\.tfvars?(?!s?\.example)(?![\w-])|\.tfvar[*?\[]",
     "Terraform state and tfvars can contain secrets in plain text. Use `terraform state list` or `terraform output` (sensitive values stay hidden)."),
    (r"(?:^|[\s/\\~'\"=])\.aws(?=$|[\s/\\'\"*])",
     "That's the local AWS credential folder. Use `aws sts get-caller-identity` to check who you're signed in as."),
]


def is_plain_check_ignore(tokens):
    """`git check-ignore <paths>` never opens the files. Only that plain form is exempt."""
    return (len(tokens) >= 2 and basename(tokens[0]) == "git" and word(tokens[1]) == "check-ignore"
            and not any("--stdin" in t or "$(" in t or "`" in t for t in tokens))


for tokens in ALL_SEGMENTS:
    text = " ".join(tokens)
    if not is_plain_check_ignore(tokens):
        for pattern, reason in SECRET_PATHS:
            if re.search(pattern, text):
                findings.append((DENY, reason))
    if re.search(r"\bdocker(?:-compose|\s+compose)\b.*\bconfig\b", text) and not re.search(
            r"\s(--quiet|-q|--services|--volumes|--profiles|--images|--hash)\b", text):
        findings.append((DENY, "`docker compose config` prints secrets from .env. Use `docker compose config --quiet` to validate."))

# ---------------------------------------------------------------------------
# GitHub CLI (regex on each segment: gh's own subcommands are simple)
# ---------------------------------------------------------------------------
GH = r"(?<![\w-])gh(?:\.exe)?[\"']?\s+"
GH_GATED = [
    (GH + r"pr\s+merge\b", "merging a pull request"),
    (GH + r"release\s+(create|delete|edit|upload)\b", "changing a release"),
    (GH + r"repo\s+(edit|delete|rename|archive)\b", "changing repository settings"),
    (GH + r"api\b.*(-X|--method)\s*=?\s*[\"']?(PUT|PATCH|DELETE|POST)\b", "a mutating GitHub API call"),
]
for tokens in ALL_SEGMENTS:
    text = " ".join(tokens)
    for pattern, action in GH_GATED:
        if re.search(pattern, text, flags=re.IGNORECASE):
            findings.append((ASK, f"This is {action}, which the owner approves (docs/workflow.md, Gate 2)."))
            break

# ---------------------------------------------------------------------------
# AWS, Terraform and Docker: find the tool in each segment and read its subcommand
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
# Operations whose output contains credentials, tokens, secrets or decrypted data...
AWS_CREDENTIAL_OP = re.compile(r"credential|password|token|secret|access-key|^assume-role|^decrypt$|^generate-data-key")
# ...except these, which only return metadata about them.
AWS_CREDENTIAL_METADATA_OPS = {"get-caller-identity", "get-credential-report", "get-access-key-last-used",
                               "get-access-key-info", "generate-credential-report"}
INFRA_REASON = "This changes AWS infrastructure or ships an image, which the owner approves (docs/workflow.md, infrastructure gate)."


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
    if (AWS_CREDENTIAL_OP.search(op) and not op.startswith("list-")
            and op not in AWS_CREDENTIAL_METADATA_OPS):
        return DENY, "This prints AWS credentials, a token, a secret or decrypted data into the transcript."
    if service == "configure":
        if op == "get" and re.search(r"secret|session_token|access_key", " ".join(args)):
            return DENY, "This prints stored AWS credentials."
        return None
    if service == "ssm" and op.startswith("get-parameter") and flags(args) & {"with-decryption", "cli-input-json", "cli-input-yaml"}:
        return DENY, "This can print decrypted secrets. Leave secrets in SSM; the app reads them at runtime."
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
    pushes = (
        words[:1] == ["push"]
        or words[:2] in (["image", "push"], ["manifest", "push"], ["compose", "push"])
        or words[:3] == ["buildx", "imagetools", "create"]
        or ("--push" in args and words[:1] in (["build"], ["buildx"], ["compose"]))
        or re.search(r"type=registry|push=true", " ".join(args)) is not None
    )
    return (ASK, INFRA_REASON) if pushes else None


for tokens in ALL_SEGMENTS:
    for i, token in enumerate(tokens):
        tool = basename(token)
        if tool not in TOOLS:
            continue
        args = [word(t) for t in tokens[i + 1:]]
        if tool == "aws":
            result = aws_decision(args)
        elif tool in ("terraform", "tofu"):
            result = terraform_decision(args)
        else:
            result = docker_decision(args, compose=(tool == "docker-compose"))
        if result:
            findings.append(result)
        break  # one tool per simple command; nested commands are their own segments

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
