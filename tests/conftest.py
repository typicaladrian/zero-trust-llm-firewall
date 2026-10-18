"""Shared test setup.

Two tiers:
- Fast tier (default, `pytest`): GLiNER2 is replaced by FakeNER, which "detects"
  exactly the entities a test registers. Everything else in main.py runs for real.
  No model download, runs in seconds.
- Model tier (`ZT_REAL_MODEL=1 pytest -m model`): loads the real GLiNER2 model and
  runs only tests marked `model`.
"""
import copy
import json
import os
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REAL_MODEL = os.getenv("ZT_REAL_MODEL") == "1"

# main.py reads AUDIT_LOG_DIR at import time; never let tests touch a real log directory.
os.environ.setdefault("AUDIT_LOG_DIR", tempfile.mkdtemp(prefix="zt-test-logs-"))


class FakeNER:
    """Stands in for GLiNER2. Reports each registered entity that appears in the text."""

    def __init__(self):
        self.known = {}  # label -> list of entity strings

    def extract_entities(self, text, entity_types, threshold=0.5, **kwargs):
        lowered = text.lower()
        found = {}
        for label, values in self.known.items():
            hits = [v for v in values if v.lower() in lowered]
            if hits:
                found[label] = hits
        return {"entities": found}


FAKE_NER = FakeNER()

if not REAL_MODEL:
    fake_gliner2 = types.ModuleType("gliner2")
    fake_gliner2.GLiNER2 = SimpleNamespace(from_pretrained=lambda name: FAKE_NER)
    sys.modules["gliner2"] = fake_gliner2

import main  # noqa: E402  (must come after the fake model is installed)


def pytest_collection_modifyitems(config, items):
    if REAL_MODEL:
        skip = pytest.mark.skip(reason="fast-tier test; relies on FakeNER")
        for item in items:
            if "model" not in item.keywords:
                item.add_marker(skip)
    else:
        skip = pytest.mark.skip(reason="needs the real GLiNER2 model (set ZT_REAL_MODEL=1)")
        for item in items:
            if "model" in item.keywords:
                item.add_marker(skip)


# ---------------------------------------------------------------------------
# Isolation: every test gets its own data directory and an empty client vault
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(main, "VAULT_FILE", str(tmp_path / "client_hashes.json"))
    main.CLIENT_HASH_VAULT.clear()
    FAKE_NER.known = {}
    yield tmp_path
    main.CLIENT_HASH_VAULT.clear()
    FAKE_NER.known = {}


@pytest.fixture
def ner():
    """Register entities the fake model should detect: ner.known = {"person": ["Jane Smith"]}."""
    return FAKE_NER


# ---------------------------------------------------------------------------
# Upstream LLM double: records exactly what would leave the building
# ---------------------------------------------------------------------------

class FakeUpstream:
    def __init__(self):
        self.calls = []
        self.reply = None  # None = echo the last user message back

    def __call__(self, **payload):
        self.calls.append(copy.deepcopy(payload))
        content = self.reply
        if content is None:
            content = next(m["content"] for m in reversed(payload["messages"]) if m["role"] == "user")
        message = SimpleNamespace(role="assistant", content=content)
        response = SimpleNamespace(
            choices=[SimpleNamespace(index=0, message=message, finish_reason="stop")],
            usage=SimpleNamespace(total_tokens=42),
        )
        response.model_dump = lambda: {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": message.content}, "finish_reason": "stop"}],
            "usage": {"total_tokens": 42},
        }
        return response

    def sent_text(self) -> str:
        """Everything sent upstream, flattened to one string for leak checks."""
        return json.dumps(self.calls)


@pytest.fixture
def upstream(monkeypatch):
    fake = FakeUpstream()
    monkeypatch.setattr(main.litellm, "completion", fake)
    return fake


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    # Not used as a context manager, so startup tasks (log pruning, report scheduler) don't run.
    return TestClient(main.app)


@pytest.fixture
def chat(client):
    def _chat(messages, model="claude-haiku-4-5-20251001", headers=None, **extra):
        return client.post("/v1/chat/completions", json={"model": model, "messages": messages, **extra}, headers=headers or {})
    return _chat
