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


def test_system_message_content_is_redacted(chat, upstream):
    chat([
        {"role": "system", "content": "Case notes: client Jane Smith, SSN 123-45-6789."},
        {"role": "user", "content": "Summarize the case notes."},
    ])
    assert_no_leak(upstream.sent_text(), SECRETS)


def test_placeholder_instructions_are_sent_alongside_client_system_prompt(chat, upstream):
    chat([
        {"role": "system", "content": "You assist the litigation team. The client is Jane Smith."},
        {"role": "user", "content": PROMPT},
    ])
    sent = upstream.calls[0]["messages"]

    assert sent[0] == main.SYSTEM_PROMPT  # decision 0009
    assert sent[1]["role"] == "system"
    assert TOKEN.search(sent[1]["content"])
    assert_no_leak(sent[1]["content"], SECRETS)


def test_placeholder_instructions_set_no_persona():
    # They sit next to the firm's own system prompt, so they must not compete with its persona.
    assert "you are" not in main.SYSTEM_PROMPT["content"].lower()


def test_system_and_user_messages_share_placeholders(chat, upstream):
    response = chat([
        {"role": "system", "content": "Case notes: client Jane Smith."},
        {"role": "user", "content": "Draft a letter to Jane Smith."},
    ])
    sent = upstream.calls[0]["messages"]

    assert "[PERSON_1]" in sent[1]["content"]
    assert "[PERSON_1]" in sent[2]["content"]
    assert "[PERSON_2]" not in upstream.sent_text()
    assert response.json()["choices"][0]["message"]["content"] == "Draft a letter to Jane Smith."


def test_redaction_round_trip_loses_no_context(chat, upstream, monkeypatch):
    vaults = []

    class RecordingVault(main.EntityVault):
        def __init__(self):
            super().__init__()
            vaults.append(self)

    monkeypatch.setattr(main, "EntityVault", RecordingVault)
    messages = [
        {"role": "system", "content": "You assist the litigation team. The client is Jane Smith."},
        {"role": "user", "content": PROMPT},
        {"role": "assistant", "content": "Here is a draft for Jane Smith to send to Acme Robotics."},
        {"role": "user", "content": "Make it firmer, and cite the SSN 123-45-6789 only once."},
    ]
    chat(messages)
    sent = upstream.calls[0]["messages"]
    assert_no_leak(upstream.sent_text(), SECRETS)

    # Apart from the placeholder instructions, the LLM gets every client message, in order,
    # and restoring the placeholders gives back exactly what the client sent.
    assert sent[0] == main.SYSTEM_PROMPT
    restored = [{**m, "content": vaults[0].deanonymize_text(m["content"])} for m in sent[1:]]
    assert restored == messages


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
