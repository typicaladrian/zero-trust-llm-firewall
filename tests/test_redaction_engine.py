"""EntityVault unit tests (fast tier). Covers promise P2's deterministic layers and P3.

See docs/product.md for the promise numbers.
"""
import hashlib
import json
import re

import pytest

import main
from helpers import TOKEN, assert_no_leak
from main import EntityVault


# ---------------------------------------------------------------------------
# Step 0: regex safety net (works without any model)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text, secret", [
    pytest.param("Her SSN is 123-45-6789 on file.", "123-45-6789", id="ssn"),
    pytest.param("Charge card 4000-1234-5678-9010 today.", "4000-1234-5678-9010", id="credit-card"),
    pytest.param("Write to jane.doe@example.com tomorrow.", "jane.doe@example.com", id="email"),
    pytest.param("Mail it to 45 Main Street, Hackensack, NJ 07601 please.", "45 Main Street", id="us-address"),
    pytest.param("Our office is at 221 Baker Street London NW1 6XE now.", "221 Baker Street", id="uk-address"),
    pytest.param("Details are posted at www.smithlegal.com today.", "smithlegal", id="url"),
    pytest.param("Wire funds via SWIFT: BOFAUS3N tomorrow.", "BOFAUS3N", id="swift"),
    pytest.param("Opposing counsel is Hogan & Hartson LLP here.", "Hartson", id="law-firm-suffix"),
    pytest.param("The letter was signed by Marcus Vance, Esq. on Friday.", "Marcus Vance", id="esquire"),
])
def test_regex_layer_redacts_structured_identifiers(text, secret):
    redacted = EntityVault().anonymize_text(text)
    assert_no_leak(redacted, [secret])
    assert TOKEN.search(redacted)


def test_overlapping_regex_matches_do_not_corrupt_text():
    # A card number directly followed by an address: the address pattern also starts at
    # the card's first digit and runs on to the ZIP, so the two spans overlap (#6).
    text = "Card 4000 1234 5678 9010 billed to 45 Main Street, Hackensack, NJ 07601 yesterday."
    vault = EntityVault()
    redacted = vault.anonymize_text(text)

    assert_no_leak(redacted, ["4000 1234", "5678 9010", "45 Main Street", "601"])
    assert vault.deanonymize_text(redacted) == text, f"Round trip broken; redacted was {redacted!r}"


def test_regex_match_nested_inside_another_is_redacted_once():
    # The email sits inside the URL match
    text = "See https://files.example.com/u/jane.doe@example.com today."
    vault = EntityVault()
    redacted = vault.anonymize_text(text)

    assert_no_leak(redacted, ["files.example", "jane.doe", "example.com"])
    assert len(TOKEN.findall(redacted)) == 1, redacted
    assert vault.deanonymize_text(redacted) == text, f"Round trip broken; redacted was {redacted!r}"


def test_partially_overlapping_regex_matches_are_merged(monkeypatch):
    # Neither span covers the other, so keeping only one would leak the other's tail
    monkeypatch.setattr(main, "REGEX_PATTERNS", {"Alpha": r"AAA BBB", "Beta": r"BBB CCC"})
    text = "Ref AAA BBB CCC end."
    vault = EntityVault()
    redacted = vault.anonymize_text(text)

    assert redacted == "Ref [ALPHA_1] end."
    assert vault.deanonymize_text(redacted) == text


def test_same_span_matches_yield_one_token_with_the_first_pattern_label(monkeypatch):
    monkeypatch.setattr(main, "REGEX_PATTERNS", {"Alpha": r"AAA BBB", "Beta": r"AAA BBB"})
    text = "Ref AAA BBB end."
    vault = EntityVault()
    redacted = vault.anonymize_text(text)

    assert redacted == "Ref [ALPHA_1] end."
    assert dict(vault.counters) == {"ALPHA": 1}
    assert vault.deanonymize_text(redacted) == text


def test_adjacent_regex_matches_stay_separate():
    # Guards against over-merging: spans that don't overlap keep their own tokens and labels
    text = "SSN 123-45-6789, jane.doe@example.com today."
    vault = EntityVault()
    redacted = vault.anonymize_text(text)

    assert redacted == "SSN [SOCIAL_SECURITY_NUMBER_1], [EMAIL_ADDRESS_1] today."
    assert vault.deanonymize_text(redacted) == text


# ---------------------------------------------------------------------------
# NER integration logic (fake model decides what is an entity)
# ---------------------------------------------------------------------------

def test_same_entity_gets_the_same_token_everywhere(ner):
    ner.known = {"person": ["Jane Smith"]}
    redacted = EntityVault().anonymize_text("Jane Smith called. Later, Jane Smith emailed.")

    tokens = TOKEN.findall(redacted)
    assert len(tokens) == 2 and tokens[0] == tokens[1]
    assert_no_leak(redacted, ["Jane Smith"])


def test_surname_alone_is_redacted_after_the_full_name(ner):
    ner.known = {"person": ["Jane Smith"]}
    redacted = EntityVault().anonymize_text("Jane Smith signed the lease. Smith then left the room.")
    assert_no_leak(redacted, ["Smith"])


def test_repeat_mention_in_a_later_chunk_is_caught_by_global_sweep(ner):
    ner.known = {"person": ["Jane Smith"]}
    filler = " ".join(["word"] * 450)  # pushes the second mention into another 400-word chunk
    text = f"Jane Smith is the plaintiff. {filler} Ms. jane smith testified."

    def first_chunk_only(chunk, labels, threshold=0.5, **kw):
        # Simulate the model missing the lowercase repeat in chunk two
        return {"entities": {"person": ["Jane Smith"]} if "Jane Smith" in chunk else {}}

    ner.extract_entities = first_chunk_only
    try:
        redacted = EntityVault().anonymize_text(text)
    finally:
        del ner.extract_entities  # restore the class method
    assert_no_leak(redacted, ["jane smith"])


def test_legal_boilerplate_in_stopwords_is_not_redacted(ner):
    ner.known = {"organization": ["Indemnifying Party", "Acme Robotics"]}
    redacted = EntityVault().anonymize_text("The Indemnifying Party shall reimburse Acme Robotics.")

    assert "Indemnifying Party" in redacted
    assert_no_leak(redacted, ["Acme Robotics"])


def test_deanonymize_restores_every_placeholder(ner):
    ner.known = {"person": ["Jane Smith"], "organization": ["Acme Robotics"]}
    vault = EntityVault()
    original = "Jane Smith sued Acme Robotics. Email jane@acme.example for details."
    redacted = vault.anonymize_text(original)

    restored = vault.deanonymize_text(redacted)
    assert restored == original


# ---------------------------------------------------------------------------
# Step 1: client hash vault (P3)
# ---------------------------------------------------------------------------

def test_synced_client_names_are_redacted_without_any_model_help(client):
    client.post("/v1/vault/sync", json={"names": ["Northbridge Capital"]})
    redacted = EntityVault().anonymize_text("We represent Northbridge Capital in the merger.")

    assert "[PROTECTED_CLIENT_1]" in redacted
    assert_no_leak(redacted, ["Northbridge"])


def test_vault_file_contains_no_plaintext_names(client, isolated_state):
    client.post("/v1/vault/sync", json={"names": ["Northbridge Capital"]})
    stored = (isolated_state / "client_hashes.json").read_text()

    assert_no_leak(stored, ["Northbridge", "northbridgecapital"])
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in json.loads(stored))


@pytest.mark.xfail(reason="#7: unsalted SHA-256 lets a guessed name be confirmed (P3, decision 0005)")
def test_vault_hashes_cannot_be_confirmed_by_guessing_a_name(client, isolated_state):
    client.post("/v1/vault/sync", json={"names": ["Northbridge Capital"]})
    stored = set(json.loads((isolated_state / "client_hashes.json").read_text()))

    attacker_guess = hashlib.sha256(b"northbridgecapital").hexdigest()
    assert attacker_guess not in stored
