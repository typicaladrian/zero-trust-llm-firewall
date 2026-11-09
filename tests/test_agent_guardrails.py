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
