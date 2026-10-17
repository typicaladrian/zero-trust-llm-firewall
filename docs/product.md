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

| # | Promise made to firms | Requirement | Verified by today |
|---|---|---|---|
| P1 | "Raw case data never leaves your network" | Every message an LLM receives in the zero-trust lane is redacted, for every role and content shape | **Partly.** Only string `content` on non-system roles is redacted. No automated test |
| P2 | Detects names, parties, case citations, docket numbers, diagnoses, medications, MRNs, card/bank numbers, TIN, SWIFT/IBAN, addresses (US and UK), SSN, driver's license, passport, email, phone | Each listed entity type is detected | `evals/benchmark.py` measures overall recall (91.4% strict on CUAD). No per-type test |
| P3 | "Cryptographic Shredding" / "irreversible SHA-256 hashing" of client lists | Client names can't be recovered from what is stored | **No.** Hashes are unsalted, so a list of likely names can be hashed and compared. See [decision 0005](decisions/0005-client-vault-stores-hashes.md) |
| P4 | Zero plaintext persistence; mappings exist only in RAM | Nothing written to disk contains original values | No test. The redacted payload is printed to stdout and ends up in Docker logs |
| P5 | Immutable metadata audit log with user identity, never prompt text | Logs have metadata only, with a verified user | No test. Log format isn't tamper-evident |
| P6 | Real-time reconstruction: associates see plain text | Placeholders in the response are fully restored | Manually via `scripts/multiturn_smoke_test.py` |
| P7 | Local auditor endpoint lets compliance staff see the exact sanitized payload | `elm-tech-auditor` returns exactly what would be sent | Manually via `scripts/stress_test.py` |
| P8 | Separate unredacted lane for public research | `public-research-base` skips redaction and streams | Manually |
| P9 | Monthly compliance and ROI report | The PDF arrives by email on the 1st with correct numbers | Manually via `/v1/admin/force-audit-delivery` |
| P10 | Redaction needs zero cloud connectivity | The engine runs offline once the image is built | Model weights are baked into the image at build time. No offline test |

Turning the "No" and "Manually" rows into automated checks is the goal of the Phase 0 eval suite. Each row should end up linked to a test file.
