"""Real-model coverage of every entity type promised to firms (P2 in docs/product.md).

Run with:  ZT_REAL_MODEL=1 pytest -m model
All names, numbers and cases below are fictional.
"""
import pytest

from helpers import assert_no_leak
from main import EntityVault

pytestmark = pytest.mark.model

PROMISED_ENTITIES = [
    # Legal and medical protected information
    ("plaintiff-name", "The plaintiff, Margaret Okonkwo, filed her complaint on March 3.", ["Okonkwo"]),
    ("defendant-name", "Defendant Trevor Lindqvist failed to appear for the deposition.", ["Lindqvist"]),
    ("case-citation", "As held in Halvorsen v. Brightwater Logistics, the clause is unenforceable.", ["Halvorsen", "Brightwater"]),
    ("law-firm", "Opposing counsel at Whitcombe Delacroix LLP sent a settlement offer.", ["Whitcombe", "Delacroix"]),
    ("docket-number", "Please file the motion under Docket No. BER-L-004821-25 by Friday.", ["004821"]),
    ("diagnosis", "Her records show a diagnosis of relapsing multiple sclerosis in 2021.", ["multiple sclerosis"]),
    ("medication", "He was prescribed Lisinopril 20mg daily after the accident.", ["Lisinopril"]),
    ("medical-record-number", "Patient medical record number MRN-77310452 is attached.", ["77310452"]),
    # Financial and personal identifiers
    ("credit-card", "The retainer was charged to card 4532 7719 0482 3361.", ["4532 7719", "0482 3361"]),
    ("bank-account", "Deposit the settlement to bank account number 004417829316.", ["004417829316"]),
    ("tax-id", "The company's tax identification number is 84-2917365.", ["84-2917365"]),
    ("iban", "Send the wire to IBAN GB29 NWBK 6016 1331 9268 19.", ["NWBK 6016", "9268 19"]),
    ("full-name", "Our new client is Priyanka Deshmukh-Rowe, a software executive.", ["Deshmukh"]),
    ("us-address", "Serve the papers at 1187 Larchmont Avenue, Teaneck, NJ 07666.", ["1187 Larchmont"]),
    ("uk-address", "Her London flat is at 14 Ashcombe Gardens, London SW6 4TU.", ["14 Ashcombe"]),
    ("ssn", "His Social Security number is 512-38-9047.", ["512-38-9047"]),
    ("drivers-license", "Her New Jersey driver's license number is K4471 82093 61842.", ["K4471"]),
    ("passport", "He travels on passport number 582916473.", ["582916473"]),
    ("email", "Reach the witness at d.marchetti@harborview.example.", ["marchetti"]),
    ("phone", "Call the client back at (201) 555-0147 after 5 pm.", ["555-0147"]),
]


@pytest.mark.parametrize("text, secrets", [pytest.param(t, s, id=i) for i, t, s in PROMISED_ENTITIES])
def test_promised_entity_type_is_redacted(text, secrets):
    redacted = EntityVault().anonymize_text(text)
    assert_no_leak(redacted, secrets)


def test_name_split_across_a_chunk_boundary_is_redacted():
    # Text is processed in 400-word chunks; put "Okonkwo" as word 401.
    filler = " ".join(["the"] * 398)
    text = f"{filler} Margaret Okonkwo signed the settlement agreement."
    redacted = EntityVault().anonymize_text(text)
    assert_no_leak(redacted, ["Okonkwo"])
