# 0001. Layered redaction pipeline
- **Status:** Accepted
- **Date:** 2026-07-14 (structure refined through 2026-08-20)

## Context
No single detector catches everything. Regex is exact but only works for structured identifiers. NER models generalize to names and context but miss oddly formatted IDs and can be inconsistent across chunks. Firms also have known client names that must always be caught, whatever the model thinks.

## Decision
Redact in fixed stages, from most to least deterministic: regex safety net → client hash vault → GLiNER2 context NER → global sweep of every value already found. Each stage only sees text the previous stages left unredacted.

## Consequences
- Structured PII (SSNs, card numbers) is caught even if the model misses it.
- The global sweep makes redaction consistent across 400-word chunks and catches repeat mentions.
- Precision depends on the hand-maintained `STOPWORDS` list. Over-redaction of legal boilerplate is the main cost.
- Every stage adds latency (about 11 s per 1,000 words on CPU, mostly NER).
