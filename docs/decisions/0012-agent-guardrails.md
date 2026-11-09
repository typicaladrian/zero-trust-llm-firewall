# 0012. Agent guardrails: owner-gated infrastructure, no secret reads, defense in depth
- **Status:** Accepted
- **Date:** 2026-11-08

## Context
From Milestone 3 on, AI agents work in a repo that can create and delete real AWS resources and that has secrets nearby: Terraform state, AWS credential caches, SSM parameters. Two things must not happen without the owner: infrastructure changes (and image pushes), and secrets or credentials appearing in an agent's transcript.

Claude Code permission rules match a command by its first word. They miss a tool run by full path (`"C:\...\aws.exe"`), after `&&`, inside `bash -c '...'` or inside a `$(...)` substitution. They also don't apply across tools: rules written for `Bash` don't cover the `PowerShell` tool.

## Decision
Layered controls, each covering a different route:

| Route | Control |
|---|---|
| Read/Edit file tools | `deny` rules in `.claude/settings.json` for `.env`, Terraform state, tfvars, `~/.aws` |
| Shell commands (Bash and PowerShell tools) | `.claude/hooks/guard_bash.py` |
| Committing secrets | `.gitignore` (state, tfvars, `.terraform/`, saved plans) |
| Merging to `main` | GitHub branch protection (server-side) |
| Production deploys | GitHub environment with the owner as required reviewer (server-side, Milestone 3 step 5) |

The hook splits a command into segments (`;`, `&&`, `||`, `|`, `&`, newlines, after joining line continuations), tokenizes each with `shlex`, strips subshell syntax, looks inside quoted command strings (`bash -c '...'`), and decides per tool:
- **Deny** reading secrets: secret-bearing paths (including globs), decrypted SSM parameters (`--with-decryption` or `--cli-input-*`), Secrets Manager values, KMS decrypt, AWS operations that return credentials or tokens, `terraform state pull`/`console`/`output -json|-raw`/`show -json` (any flag spelling).
- **Ask** for changes: `terraform apply/destroy/import/test/refresh`, state edits and migration, AWS operations not on a read-only allowlist (`describe-`, `list-`, `get-`, ...), and image pushes (`docker push`, compose, manifest, buildx `--push`/registry output).
- Read-only AWS is an **allowlist**, so an unfamiliar or new operation asks by default (fail closed).

The first version was reviewed adversarially: about 50 of 70 attack commands got the wrong decision (for example, `$(...)` inside a double-quoted commit message, a `git check-ignore --stdin` exception that read files, `--json` spelled with two dashes, and the PowerShell tool not being covered). Every bypass is now a test case in `tests/test_agent_guardrails.py`.

## Consequences
- **Known limitations, accepted:** the hook reads command *text*. It does not see code it can't read: a Python or boto3 script, a shell script on disk, a container running the AWS CLI (`docker run amazon/aws-cli ...`), `docker exec ... printenv`, or an unforeseen shell construct. It is a guardrail, not a sandbox. The server-side controls (branch protection, environment approval) and least-privilege AWS roles are what hold if it's bypassed.
- **Accepted false positives:** a command that only *mentions* a guarded command (`grep "terraform apply" docs/`) may ask; `aws ecr get-login-password` is denied, so only the owner or CI pushes images.
- When the client vault moves to DynamoDB (Milestone 4), `aws dynamodb scan` on that table would print client data; the hook will need a rule for it then.
- New guard cases are added as tests first, the same way as product bugs.
