"""Static checks on the Dockerfile and .dockerignore (issue #26, step 2: Lambda-ready image).

These tests read the build files as text. They cannot prove the image builds, fits under Lambda's
10 GB limit or runs offline: the CI `container` job (scripts/container_check.sh) proves that. What
they do is stop someone from quietly reordering or deleting the lines that make it work:

  * CPU-only PyTorch must be installed BEFORE requirements.txt, or pip pulls the CUDA wheels
    (about 5 GB bigger: roughly 8 GB instead of 3 GB, slower to pull and start). A static test
    cannot see a LATER silent swap, e.g. gliner2 asking for a torch the CPU build doesn't satisfy;
    the smoke test's `torch.version.cuda is None` check catches that one.
  * HF_HOME must be set BEFORE the model download and HF_HUB_OFFLINE AFTER it.
  * The Lambda Web Adapter sees raw prompts on Lambda, so it is pinned by digest.
  * .dockerignore keeps secrets and dev files out of the build context (non-negotiable #2).

The Dockerfile is parsed by meaning (continuations joined, comments dropped, instruction order
compared), not matched as exact text, so reformatting it doesn't break these tests.

Promises protected: P10 (offline), P1 (adapter supply chain), non-negotiable #2 (.env).
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODEL_DOWNLOAD_MARKER = "from_pretrained"   # the RUN that bakes the model weights into the image
CPU_TORCH_INDEX = "download.pytorch.org/whl/cpu"


def parse_dockerfile(text: str) -> list[tuple[str, str]]:
    """Return (INSTRUCTION, arguments) pairs in file order, with comments dropped and
    backslash-continued lines joined."""
    logical, buffer = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if buffer and line.startswith("#"):      # a comment in the middle of a continuation
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append(buffer + line)
        buffer = ""
    if buffer:
        logical.append(buffer)
    parsed = []
    for entry in logical:
        instruction, _, args = entry.partition(" ")
        parsed.append((instruction.upper(), args.strip()))
    return parsed


def env_assignments(args: str) -> dict[str, str]:
    """Parse the argument of an ENV instruction: `KEY=value KEY2=value2` or `KEY value`."""
    if "=" in args.split(" ")[0]:
        return dict(re.findall(r'(\w+)=("[^"]*"|\S+)', args))
    key, _, value = args.partition(" ")
    return {key: value}


@pytest.fixture(scope="module")
def instructions():
    return parse_dockerfile((ROOT / "Dockerfile").read_text(encoding="utf-8"))


def index_of_env(instructions, key, value=None):
    """Position of the first ENV instruction that sets `key` (to `value`, if given)."""
    for i, (name, args) in enumerate(instructions):
        if name == "ENV":
            assigned = env_assignments(args)
            if key in assigned and (value is None or assigned[key].strip('"') == value):
                return i
    return None


def index_of_run(instructions, *needles):
    """Position of the first RUN instruction containing every needle."""
    for i, (name, args) in enumerate(instructions):
        if name == "RUN" and all(n in args for n in needles):
            return i
    return None


# --- PyTorch: CPU wheels first ------------------------------------------------------------------

def test_cpu_torch_installed_before_requirements(instructions):
    """P10 / image size: pip resolves torch from requirements.txt to the CUDA build unless a CPU
    build is already installed, which adds about 5 GB (8 GB instead of 3 GB) for a GPU that
    Lambda doesn't have."""
    cpu = index_of_run(instructions, "torch", CPU_TORCH_INDEX)
    reqs = index_of_run(instructions, "-r requirements.txt")
    assert cpu is not None, "Dockerfile must install torch from the CPU-only index"
    assert reqs is not None, "Dockerfile must install requirements.txt"
    assert cpu < reqs, "CPU-only torch must be installed BEFORE requirements.txt"


# --- Hugging Face cache and offline mode --------------------------------------------------------

def test_hf_home_before_model_download_and_offline_after(instructions):
    """P10: weights are cached in /opt/hf (readable by the non-root Lambda user; /root is not) and
    the image then refuses to touch the network. Offline mode must come AFTER the download or the
    download itself fails."""
    download = index_of_run(instructions, MODEL_DOWNLOAD_MARKER)
    hf_home = index_of_env(instructions, "HF_HOME", "/opt/hf")
    offline = index_of_env(instructions, "HF_HUB_OFFLINE", "1")
    assert download is not None, "Dockerfile must pre-download the model"
    assert hf_home is not None, "ENV HF_HOME=/opt/hf is missing"
    assert offline is not None, "ENV HF_HUB_OFFLINE=1 is missing"
    assert hf_home < download, "HF_HOME must be set BEFORE the model download"
    assert download < offline, "HF_HUB_OFFLINE=1 must be set AFTER the model download"


def test_litellm_uses_local_cost_map(instructions):
    """P10: LiteLLM must not fetch its price list from the internet at import time."""
    assert index_of_env(instructions, "LITELLM_LOCAL_MODEL_COST_MAP", "True") is not None


# --- Lambda Web Adapter -------------------------------------------------------------------------

def test_lambda_adapter_pinned_by_digest(instructions):
    """P1: on Lambda the adapter forwards every request, so it sees raw prompts. A tag can be
    re-pointed at different bytes; a digest cannot."""
    copies = [args for name, args in instructions
              if name == "COPY" and "aws-lambda-adapter" in args]
    assert copies, "Dockerfile must COPY the Lambda Web Adapter"
    copy = copies[0]
    assert re.search(r"--from=\S*aws-lambda-adapter\S*@sha256:[0-9a-f]{64}\b", copy), \
        "pin the adapter image by @sha256 digest"
    assert ":latest" not in copy
    assert copy.split()[-1].rstrip("/").startswith("/opt/extensions"), \
        "Lambda only loads extensions from /opt/extensions/"


# --- Things that must stay out of (or stay the same in) the image -------------------------------

def test_no_lambda_only_settings_in_image(instructions):
    """Lambda-only settings come from Terraform. Baking them in would change how the on-prem
    appliance behaves (HOME, audit directory) or be dead weight."""
    forbidden = []
    for name, args in instructions:
        if name == "ENV":
            forbidden += [k for k in env_assignments(args)
                          if k in {"AUDIT_LOG_DIR", "HOME"} or k.startswith("AWS_LWA_")]
    assert not forbidden, f"set these in Terraform, not in the image: {forbidden}"


def test_cmd_still_serves_uvicorn_on_8000(instructions):
    """The Docker Compose appliance starts the image with its default CMD."""
    cmds = [args for name, args in instructions if name == "CMD"]
    assert cmds, "Dockerfile needs a CMD"
    assert "uvicorn" in cmds[-1] and "main:app" in cmds[-1]
    assert re.search(r'"--port",\s*"8000"|--port[ =]8000', cmds[-1])


# --- .dockerignore ------------------------------------------------------------------------------

def dockerignore_patterns() -> list[str]:
    path = ROOT / ".dockerignore"
    assert path.exists(), ".dockerignore is missing"
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()]
    return [ln for ln in lines if ln and not ln.startswith("#") and not ln.startswith("!")]


def _pattern_regex(pattern: str) -> re.Pattern:
    """Translate one .dockerignore pattern into a regex over slash-separated paths.

    Docker's rules (a subset, enough for this repo): patterns are matched from the context root,
    so `.env*` does NOT match `scripts/.env`; `**/` matches any number of leading directories;
    `*` and `?` never cross a `/`; matching is case-sensitive.
    """
    pattern = pattern.strip("/")
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out)


def is_ignored(path: str, patterns: list[str]) -> bool:
    """True if Docker would leave `path` out of the build context.

    A pattern that matches a directory excludes everything inside it, so every parent prefix of
    the path is tried too.
    """
    parts = path.split("/")
    prefixes = ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]
    return any(_pattern_regex(p).fullmatch(prefix) for p in patterns for prefix in prefixes)


@pytest.mark.parametrize("path", [
    ".env",                      # non-negotiable #2
    ".env.local",
    "scripts/.env",              # .dockerignore is root-anchored: needs `**/.env*` to catch these
    "docs/deep/.env.production",
    "venv",
    ".git",
    "private",                   # local business notes (gitignored, but still on the owner's disk)
    "evals",
    "evals/output/report.txt",
    "tests",
    "tests/conftest.py",
    "zt_firewall/__pycache__",
    "__pycache__",
    ".claude",
    "infra",                     # Terraform files (step 4+)
    "terraform.tfstate",         # state can hold secrets (.gitignore already keeps it out of git)
    "scripts/prod.tfvars",
    "audit_log.db",
])
def test_dockerignore_excludes(path):
    assert is_ignored(path, dockerignore_patterns()), f"{path} must be excluded by .dockerignore"


def test_dockerignore_has_no_exceptions():
    """A `!pattern` line re-includes files and could silently bring a secret back into the build
    context. If one is ever needed, review it against the secret paths above first."""
    path = ROOT / ".dockerignore"
    negations = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
                 if ln.strip().startswith("!")]
    assert not negations, f"unexpected re-include lines in .dockerignore: {negations}"


def test_dockerignore_matcher_follows_docker_semantics():
    """Guards the matcher itself, so the exclude tests above can't pass for the wrong reason."""
    assert is_ignored(".env", [".env*"])
    assert not is_ignored("scripts/.env", [".env*"])          # root-anchored
    assert is_ignored("scripts/.env", ["**/.env*"])
    assert not is_ignored(".ENV", [".env*"])                  # case-sensitive
    assert is_ignored("tests/test_x.py", ["tests/"])          # a directory excludes its contents
    assert not is_ignored("main.py", ["*.md"])


@pytest.mark.parametrize("name", ["assets", "assets/logo.png", "main.py", "zt_firewall", "requirements.txt"])
def test_dockerignore_keeps_what_the_build_copies(name):
    """The Dockerfile COPYs these; ignoring them would break the build."""
    assert not is_ignored(name, dockerignore_patterns()), f"{name} must not be in .dockerignore"
