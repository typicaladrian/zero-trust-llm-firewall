# Product

## Who it's for

Small and mid-size law firms that want to use frontier LLMs for drafting, contract analysis and research, but can't send client information to a public AI service. ABA Formal Opinion 512 says lawyers need informed client consent before putting information about a representation into public GenAI tools, and Model Rule 1.6 requires confidentiality.

The people involved in buying it:
- **Managing partners**: want the productivity gain without the ethics exposure.
- **IT directors**: want a plug-in appliance with no ongoing engineering work.
- **Compliance staff**: want proof that it works (audit reports, the auditor lane).
- **Associates**: just use Open WebUI. Redaction has to be invisible and must not degrade answers.

## How it's delivered

A preconfigured mini PC installed on the firm's LAN and managed remotely: engine updates, report delivery and hardware replacement. The firm brings its own API keys (BYOK) and pays providers directly. The default model set is Claude Opus and Claude Haiku. This repository is the software that runs on that appliance.

## Product promises → requirements

Everything the firm is told becomes a requirement with a check. A promise with no automated check is a risk: a refactor could quietly break it while the sales material keeps promising it.

| # | Promise made to firms | Requirement | Verified by | Status |
|---|---|---|---|---|
| P1 | "Raw case data never leaves your network" | Every message an LLM receives in the zero-trust lane is redacted, for every role and content shape | [test_zero_trust_lane.py](../tests/test_zero_trust_lane.py) | System-role messages are redacted with the same vault as the rest of the conversation (#4). **Gaps:** multi-part messages aren't redacted (xfail, #5). Message fields other than `content` (`name`, `tool_calls`, `function_call`) leave unredacted (not yet tracked) |
| P2 | Detects names, parties, case citations, docket numbers, diagnoses, medications, MRNs, card/bank numbers, TIN, SWIFT/IBAN, addresses (US and UK), SSN, driver's license, passport, email, phone | Each listed entity type is detected | [test_entity_coverage.py](../tests/model/test_entity_coverage.py) (one test per type), [test_redaction_engine.py](../tests/test_redaction_engine.py), [benchmark.py](../evals/benchmark.py) (91.4% strict CUAD recall) | All 20 types pass. Overlapping regex matches are merged before replacement (#6) |
| P3 | "Cryptographic Shredding" / "irreversible SHA-256 hashing" of client lists | Client names can't be recovered from what is stored | [test_redaction_engine.py](../tests/test_redaction_engine.py) | No plaintext stored. **Gap:** unsalted hashes can be confirmed by guessing (xfail, [decision 0005](decisions/0005-client-vault-stores-hashes.md)) |
| P4 | Zero plaintext persistence; mappings exist only in RAM | Nothing written to disk contains original values | [test_audit_log.py](../tests/test_audit_log.py) | Audit file and stdout contain no secrets |
| P5 | Immutable metadata audit log with user identity, never prompt text | Logs have metadata only, with a verified user | [test_audit_log.py](../tests/test_audit_log.py) | Metadata-only and JWT attribution pass. Tamper-evidence isn't built |
| P6 | Real-time reconstruction: associates see plain text | Placeholders in the response are fully restored | [test_zero_trust_lane.py](../tests/test_zero_trust_lane.py), [test_redaction_engine.py](../tests/test_redaction_engine.py) (exact round trip with overlapping regex matches) | Pass. Placeholder instructions are sent even next to a client system prompt, and every client message reaches the LLM in order; restoring gives back each message when entities appear in full form, while partial names are restored as the full name ([decision 0009](decisions/0009-always-send-placeholder-instructions.md)) |
| P7 | Local auditor endpoint lets compliance staff see the exact sanitized payload | `elm-tech-auditor` returns the redacted text and never calls an LLM | [test_zero_trust_lane.py](../tests/test_zero_trust_lane.py) | Pass. **Gap:** it shows only the last user message, not system messages, earlier turns or the placeholder instructions (not yet tracked) |
| P8 | Separate unredacted lane for public research | `public-research-base` skips redaction | [test_zero_trust_lane.py](../tests/test_zero_trust_lane.py) | Pass |
| P9 | Monthly compliance and ROI report | The PDF arrives by email on the 1st with correct numbers | Manual: `/v1/admin/force-audit-delivery` | Not automated |
| P10 | Redaction needs zero cloud connectivity | The engine runs offline once the image is built | None | Not tested |

Known gaps are written as tests marked `xfail(strict=True)`: they describe the correct behavior and are expected to fail. When a fix makes one pass, the strict marker fails the run until the marker is removed, so gaps can't be closed (or reopened) silently.
