"""End-to-end behavior of POST /v1/chat/completions per lane (fast tier).

P1: raw client data never leaves the network. Everything sent upstream is captured
by the `upstream` fixture and checked for leaks.
"""
import pytest

import main
from helpers import TOKEN, assert_no_leak

SECRETS = ["Jane Smith", "Acme Robotics", "123-45-6789"]
PROMPT = "Draft a demand letter from Jane Smith (SSN 123-45-6789) to Acme Robotics."


@pytest.fixture(autouse=True)
def known_entities(ner):
    ner.known = {"person": ["Jane Smith"], "organization": ["Acme Robotics"]}


# ---------------------------------------------------------------------------
# Zero-trust lane (P1, P6)
# ---------------------------------------------------------------------------

def test_user_message_is_redacted_before_it_reaches_the_llm(chat, upstream):
    response = chat([{"role": "user", "content": PROMPT}])

    assert response.status_code == 200
    assert len(upstream.calls) == 1
    assert_no_leak(upstream.sent_text(), SECRETS)


def test_earlier_turns_are_redacted_too(chat, upstream):
    chat([
        {"role": "user", "content": "My client is Jane Smith."},
        {"role": "assistant", "content": "Understood, I will refer to Jane Smith carefully."},
        {"role": "user", "content": "Now write to Acme Robotics on her behalf."},
    ])
    assert_no_leak(upstream.sent_text(), SECRETS)


def test_placeholder_instructions_are_added_when_no_system_prompt(chat, upstream):
    chat([{"role": "user", "content": PROMPT}])
    sent = upstream.calls[0]["messages"]
    assert sent[0] == main.SYSTEM_PROMPT


def test_llm_reply_is_restored_to_plaintext_for_the_user(chat, upstream):
    # The fake LLM echoes the redacted prompt, placeholders included.
    response = chat([{"role": "user", "content": PROMPT}])
    content = response.json()["choices"][0]["message"]["content"]

    assert content == PROMPT
    assert not TOKEN.search(content)


def test_zero_trust_lane_never_streams(chat, upstream):
    chat([{"role": "user", "content": PROMPT}], stream=True)
    assert upstream.calls[0]["stream"] is False  # decision 0004


@pytest.mark.xfail(reason="#4: system-role messages skip redaction (P1)")
def test_system_message_content_is_redacted(chat, upstream):
    chat([
        {"role": "system", "content": "Case notes: client Jane Smith, SSN 123-45-6789."},
        {"role": "user", "content": "Summarize the case notes."},
    ])
    assert_no_leak(upstream.sent_text(), SECRETS)


@pytest.mark.xfail(reason="#5: multi-part (list) message content skips redaction (P1)")
def test_multipart_message_content_is_redacted(chat, upstream):
    upstream.reply = "ok"
    chat([{"role": "user", "content": [{"type": "text", "text": PROMPT}]}])
    assert_no_leak(upstream.sent_text(), SECRETS)


# ---------------------------------------------------------------------------
# Auditor lane (P7) and public research lane (P8)
# ---------------------------------------------------------------------------

def test_auditor_lane_shows_redacted_text_without_calling_the_llm(chat, upstream):
    response = chat([{"role": "user", "content": PROMPT}], model="elm-tech-auditor")
    content = response.json()["choices"][0]["message"]["content"]

    assert upstream.calls == []
    assert TOKEN.search(content)
    assert_no_leak(content, SECRETS)


def test_public_research_lane_is_unredacted_by_design(chat, upstream):
    chat([{"role": "user", "content": "What did the court hold in Marbury v. Madison?"}], model="public-research-base")

    sent = upstream.calls[0]
    assert sent["model"] == "gpt-4o-mini"
    assert sent["messages"][-1]["content"] == "What did the court hold in Marbury v. Madison?"
    assert sent["messages"][0]["role"] != "system"  # no placeholder instructions added
