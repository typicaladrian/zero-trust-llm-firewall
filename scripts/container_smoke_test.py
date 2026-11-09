"""Smoke test that runs INSIDE the built image (issue #26, step 2). Standard library only.

    docker exec -i <container> python - < scripts/container_smoke_test.py

scripts/container_check.sh starts the container the way Lambda will run it (read-only root
filesystem, non-root user, no network) and pipes this file into it. The app listens on 127.0.0.1
inside the container, so the check works even with `--network none` (loopback still exists).

It proves, with synthetic data only:
  1. the app starts offline (the model loads from /opt/hf, nothing is downloaded)  -> P10
  2. the zero-trust auditor lane redacts an SSN (regex layer) and a person name (GLiNER2 model),
     so the real model really runs offline                                           -> P10, P7
  3. the audit file written on the way holds metadata only, never the raw values    -> P4, P5
  4. PyTorch is the CPU build (a CUDA build would not fit in Lambda's 10 GB)
  5. no .env file was baked into the image                                          -> non-negotiable #2
"""
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"
READY_TIMEOUT_S = 300            # the model load dominates start-up
FAKE_SSN = "123-45-6789"         # synthetic
FAKE_NAME = "Maria Gonzalez"     # synthetic
AUDIT_DIR = os.environ.get("AUDIT_LOG_DIR", "/app/logs")

failures = []


def check(ok: bool, message: str) -> None:
    print(("PASS  " if ok else "FAIL  ") + message)
    if not ok:
        failures.append(message)


def wait_until_ready() -> bool:
    """Uvicorn only opens the port after startup_routines has loaded the model (decision 0010),
    so a successful GET /v1/models means the model is loaded."""
    deadline = time.time() + READY_TIMEOUT_S
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE}/v1/models", timeout=5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    return False


def audit_request() -> str:
    body = json.dumps({
        "model": "elm-tech-auditor",
        "messages": [{
            "role": "user",
            "content": f"Our client {FAKE_NAME} (SSN {FAKE_SSN}) asked us to review the lease.",
        }],
    }).encode()
    req = urllib.request.Request(f"{BASE}/v1/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.load(resp)["choices"][0]["message"]["content"]


def main() -> int:
    ready = wait_until_ready()
    check(ready, f"app answers GET /v1/models within {READY_TIMEOUT_S}s (model loaded offline)")
    if not ready:
        return 1

    try:
        redacted = audit_request()
    except Exception as exc:                      # HTTP 500 etc.: report it, don't hide it
        check(False, f"auditor lane request succeeded ({exc!r})")
        return 1
    check(FAKE_SSN not in redacted, "auditor output does not contain the raw SSN")
    check(re.search(r"\[SOCIAL_SECURITY_NUMBER_\d+\]", redacted) is not None,
          "auditor output has an SSN placeholder")
    check(FAKE_NAME not in redacted, "auditor output does not contain the raw person name (GLiNER2)")
    check(len(set(re.findall(r"\[[A-Z_()/]+_\d+\]", redacted))) >= 2,
          "auditor output has at least two distinct placeholders (SSN and name)")

    audit_files = glob.glob(os.path.join(AUDIT_DIR, "audit_*.jsonl"))
    check(bool(audit_files), f"audit file was written under {AUDIT_DIR}")
    for path in audit_files:
        text = open(path, encoding="utf-8").read()
        check(FAKE_SSN not in text and FAKE_NAME not in text, f"{os.path.basename(path)} holds metadata only")

    import torch                                   # heavy import, but already installed
    check(torch.version.cuda is None, f"PyTorch is the CPU build (torch.version.cuda={torch.version.cuda})")

    check(not os.path.exists("/app/.env"), "/app/.env is not in the image")

    print(f"\n{len(failures)} failure(s)" if failures else "\nAll container smoke checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
