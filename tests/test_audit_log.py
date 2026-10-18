"""Audit log guarantees (fast tier). P4: no plaintext persistence. P5: metadata-only, attributed log."""
import json
from datetime import datetime

import jwt
import pytest

from helpers import assert_no_leak

SECRET_PROMPT = "Client Jane Smith (SSN 123-45-6789) wants to sue Acme Robotics."
SECRETS = ["Jane Smith", "123-45-6789", "Acme Robotics"]


@pytest.fixture(autouse=True)
def known_entities(ner):
    ner.known = {"person": ["Jane Smith"], "organization": ["Acme Robotics"]}


def read_audit_entries(log_dir):
    path = log_dir / f"audit_{datetime.now().strftime('%Y_%m')}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_audit_entry_has_metadata_and_no_prompt_text(chat, upstream, isolated_state):
    chat([{"role": "user", "content": SECRET_PROMPT}])

    raw = (isolated_state / f"audit_{datetime.now().strftime('%Y_%m')}.jsonl").read_text()
    assert_no_leak(raw, SECRETS)

    [entry] = read_audit_entries(isolated_state)
    assert entry["tokens_anonymized"] >= 3
    assert entry["upstream_tokens"] == 42
    assert {"timestamp", "user", "model", "entity_breakdown", "latency_ms"} <= entry.keys()


def test_redacted_payload_printed_to_stdout_contains_no_secrets(chat, upstream, capsys):
    chat([{"role": "user", "content": SECRET_PROMPT}])
    assert_no_leak(capsys.readouterr().out, SECRETS)


def test_open_webui_background_prompts_are_not_logged(chat, upstream, isolated_state):
    chat([{"role": "user", "content": "Generate a concise, 3-5 word title for this chat."}])
    assert read_audit_entries(isolated_state) == []


# ---------------------------------------------------------------------------
# User attribution via Open WebUI's signed JWT
# ---------------------------------------------------------------------------

def test_user_comes_from_a_validly_signed_jwt(chat, upstream, isolated_state, monkeypatch):
    monkeypatch.setenv("WEBUI_SECRET_KEY", "test-secret")
    token = jwt.encode({"email": "partner@firm.test"}, "test-secret", algorithm="HS256")

    chat([{"role": "user", "content": "hello"}], headers={"x-openwebui-user-jwt": token})
    assert read_audit_entries(isolated_state)[0]["user"] == "partner@firm.test"


def test_jwt_signed_with_another_key_is_flagged(chat, upstream, isolated_state, monkeypatch):
    monkeypatch.setenv("WEBUI_SECRET_KEY", "test-secret")
    forged = jwt.encode({"email": "partner@firm.test"}, "attacker-key", algorithm="HS256")

    chat([{"role": "user", "content": "hello"}], headers={"x-openwebui-user-jwt": forged})
    assert read_audit_entries(isolated_state)[0]["user"] == "ERROR_INVALID_SIGNATURE"


def test_missing_secret_is_flagged_instead_of_trusting_the_jwt(chat, upstream, isolated_state, monkeypatch):
    monkeypatch.delenv("WEBUI_SECRET_KEY", raising=False)
    token = jwt.encode({"email": "partner@firm.test"}, "anything", algorithm="HS256")

    chat([{"role": "user", "content": "hello"}], headers={"x-openwebui-user-jwt": token})
    assert read_audit_entries(isolated_state)[0]["user"] == "ERROR_NO_SECRET_CONFIGURED"
