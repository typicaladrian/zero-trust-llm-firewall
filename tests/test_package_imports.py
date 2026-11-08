"""Import-time behavior of the zt_firewall package (#18).

Importing the redaction engine must stay cheap: no GLiNER2 model, no torch, and no
dependency on main.py. That keeps Lambda cold starts short and lets the engine be
used outside the web app (e.g. a queue worker).
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Runs in a fresh interpreter: this test session has already imported main and installed
# conftest's fake gliner2 module, so an in-process check could pass while testing the wrong thing.
PROBE = """
import sys
import zt_firewall.redaction.engine
from zt_firewall.redaction import ner

assert "gliner2" not in sys.modules, "importing the engine imported gliner2"
assert "torch" not in sys.modules, "importing the engine imported PyTorch"
assert "main" not in sys.modules, "the engine imports main (circular dependency)"
assert ner.get_model.cache_info().currsize == 0, "the model was loaded at import time"
print("ok")
"""


def test_importing_engine_does_not_load_the_model():
    result = subprocess.run(
        [sys.executable, "-c", PROBE], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
