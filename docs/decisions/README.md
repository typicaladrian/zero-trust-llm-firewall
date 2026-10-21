# Decision records

Short notes on significant design choices: what was decided, why, and what it costs. They stop future contributors, human or AI, from undoing a deliberate choice without knowing the reason.

**When to write one:** you picked between real alternatives, changed a core dependency, or made a trade-off that someone might later "fix" by mistake.

**Format:** `NNNN-short-title.md`, numbered in order, with these sections:

```markdown
# NNNN. Title
- **Status:** Accepted | Superseded by NNNN | Deprecated
- **Date:** YYYY-MM-DD

## Context
## Decision
## Consequences
```

Never edit an accepted record to reverse it. Write a new one that supersedes it.

Records 0001–0007 were reconstructed in October 2026 from the commit history and the owner's account of past decisions.

| # | Decision | Status |
|---|---|---|
| [0001](0001-layered-redaction-pipeline.md) | Layered redaction pipeline | Accepted |
| [0002](0002-ner-engine-gliner2.md) | GLiNER2 as the NER engine | Accepted |
| [0003](0003-per-request-entity-vault.md) | Per-request in-memory entity vault | Accepted |
| [0004](0004-no-streaming-in-zero-trust-lane.md) | No streaming in the zero-trust lane | Accepted |
| [0005](0005-client-vault-stores-hashes.md) | Client vault stores hashes only | Accepted (known weakness) |
| [0006](0006-jsonl-audit-log-and-pdf-reports.md) | JSONL audit log + emailed PDF reports | Accepted |
| [0007](0007-litellm-provider-routing.md) | LiteLLM for provider routing | Accepted |
| [0008](0008-regex-overlap-union-merge.md) | Merge overlapping regex matches into their union | Accepted |
| [0009](0009-always-send-placeholder-instructions.md) | Always send the placeholder instructions as their own system message | Accepted |
