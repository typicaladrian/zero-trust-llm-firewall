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


# ---------------------------------------------------------------------------
# AWS, Terraform and Docker (Milestone 3, #26)
# Infrastructure changes and image pushes need the owner; reading secrets, Terraform state,
# tfvars or local AWS credentials is never allowed, however the binary is spelled.
# ---------------------------------------------------------------------------

AWS = r'"C:\Program Files\Amazon\AWSCLIV2\aws.exe"'  # raw string: "\a" would otherwise be a bell character
STATE = "terraform" + ".tfstate"


@pytest.mark.parametrize("command", [
    "aws ssm get-parameter --name /zt/key --with-decryption",
    "aws ssm get-parameters-by-path --path /zt --with-decryption --recursive",
    "aws secretsmanager get-secret-value --secret-id zt/key",
    "aws configure export-credentials --format env",
    "aws ecr get-login-password --region us-east-1",
    "aws sts get-session-token",
    f"{AWS} configure export-credentials",
    "terraform state pull",
    "terraform -chdir=infra/live output -json",
    "terraform output -raw function_url",
    "terraform show -json",
    "terraform console",
    f"cat infra/live/{STATE}",
    rf"type infra\live\{STATE}.backup",
    "cat infra/live/prod.tfvars",
    "cat ~/.aws/credentials",
    "ls ~/.aws/login/cache",
    f"git check-ignore -q infra/{STATE} && cat infra/{STATE}",  # the exception covers check-ignore only
])
def test_secret_and_state_access_is_denied(command):
    assert decision(command) == "deny"


@pytest.mark.parametrize("command", [
    "terraform apply",
    "terraform -chdir=infra/live apply tfplan",
    "terraform destroy -auto-approve",
    "tofu apply",
    "terraform import aws_s3_bucket.state zt-tfstate",
    "terraform state rm aws_lambda_function.proxy",
    "terraform force-unlock 1234",
    "aws lambda update-function-code --function-name zt-proxy --image-uri x",
    "aws --region us-east-1 s3 mb s3://zt-tfstate",
    "aws s3 cp evals/output/report.txt s3://bucket/",
    "aws s3 rm s3://bucket/key",
    "aws lambda invoke --function-name zt-proxy out.json",
    "aws iam create-role --role-name x --assume-role-policy-document file://p.json",
    f"{AWS} ecr delete-repository --repository-name zt",
    r"/c/Program\ Files/Amazon/AWSCLIV2/aws.exe budgets create-budget --account-id 1 --budget file://b.json",
    "docker push 123.dkr.ecr.us-east-1.amazonaws.com/zt:abc",
    "docker image push zt:abc",
    "docker buildx build --platform linux/amd64 --push -t zt:abc .",
    "terraform plan -out tfplan && terraform apply tfplan",
])
def test_infrastructure_changes_ask_the_owner(command):
    assert decision(command) == "ask"


@pytest.mark.parametrize("command", [
    "aws login",
    "aws sts get-caller-identity",
    "aws --profile default lambda get-function --function-name zt-proxy",
    "aws ecr describe-images --repository-name zt",
    "aws lambda list-functions --region us-east-1",
    "aws logs tail /aws/lambda/zt-proxy --since 10m",
    "aws s3 ls s3://zt-tfstate",
    "aws ssm get-parameter --name /zt/region",
    "aws configure set region us-east-1",
    "aws configure list",
    f"{AWS} --version",
    "terraform init",
    "terraform -chdir=infra/live plan -out tfplan",
    "terraform validate",
    "terraform fmt -check -recursive infra",
    "terraform output",
    "terraform state list",
    "docker build -t zt:abc .",
    "docker images",
    "git commit -m 'Docs: explain when terraform apply needs approval'",
    "git add .gitignore infra/live/main.tf",
    f"git check-ignore -v infra/live/{STATE} infra/live/prod.tfvars",
])
def test_everyday_infrastructure_commands_are_allowed(command):
    assert decision(command) == "allow"


# ---------------------------------------------------------------------------
# Bypasses found by the adversarial review of #26. Each was allowed before the fix.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    # $(...) and backticks still run inside double-quoted messages
    f'gh pr create --title t --body "$(cat {DOT})"',
    f'git commit -m "x $(cat {DOT})"',
    f'git commit -m "x `cat {DOT}`"',
    # git check-ignore exception abused to read files
    f"git check-ignore --stdin -n -v < {DOT}",
    f"git check-ignore -n -v $(cat {DOT})",
    f"git check-ignore -v x & cat {DOT}",
    # flag spellings Terraform accepts
    "terraform output --json",
    "terraform output -json=true",
    "terraform output --raw function_url",
    "terraform show --json",
    # credential-printing AWS calls
    "aws sso get-role-credentials --role-name r --account-id 1 --access-token t",
    "aws cognito-identity get-credentials-for-identity --identity-id x",
    "aws iam create-access-key --user-name ci",
    "aws kms decrypt --ciphertext-blob fileb://c",
    """aws ssm get-parameter --cli-input-json '{"Name": "/zt/key", "WithDecryption": true}'""",
    # globs and directories around secret files
    "grep -r . ~/.aws",
    "cat ~/.aws/*",
    "cat ~/.aws/cred*",
    "cat infra/*.tfst*",
    "cat infra/live/prod.tfvars.json",
])
def test_review_bypasses_of_secret_rules_are_denied(command):
    assert decision(command) == "deny"


@pytest.mark.parametrize("command", [
    'git commit -m "$(terraform apply -auto-approve)"',
    "terraform -chdir=infra/live \\\napply",
    "docker images & terraform apply",
    "aws s3 ls & aws s3 rm s3://b/k",
    "docker compose push",
    "docker-compose push",
    "docker --context prod push x",
    "docker -H tcp://h:2376 push x",
    "docker manifest push zt:latest",
    "docker buildx bake --push",
    "docker buildx imagetools create -t zt:b zt:a",
    "docker buildx build --output type=registry -t zt:abc .",
    "terraform test",
    "terraform workspace delete -force staging",
    "terraform init -migrate-state",
    "bash -c 'terraform apply -auto-approve'",
    "echo $(terraform apply -auto-approve)",
    "(cd infra/live && terraform apply)",
    "AWS_PROFILE=dev aws lambda delete-function --function-name zt",
    "& 'C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe' s3 rm s3://b/k",
])
def test_review_bypasses_of_owner_gates_ask(command):
    assert decision(command) == "ask"


@pytest.mark.parametrize("command", [
    "docker compose config --services",
    "docker compose config --quiet",
    "git commit -m 'Docs: why $(cat x) is blocked in messages'",  # single quotes: bash runs nothing
    "terraform -chdir=infra/live init",
    "aws sts get-caller-identity --output json 2>&1",
])
def test_review_false_positives_are_allowed(command):
    assert decision(command) == "allow"


def test_powershell_tool_is_guarded_too():
    # The hook must also be registered for the PowerShell tool, or none of this applies there.
    settings = json.loads((HOOK.parent.parent / "settings.json").read_text())
    matchers = [entry["matcher"] for entry in settings["hooks"]["PreToolUse"]]
    assert any("PowerShell" in m.split("|") and "Bash" in m.split("|") for m in matchers)
