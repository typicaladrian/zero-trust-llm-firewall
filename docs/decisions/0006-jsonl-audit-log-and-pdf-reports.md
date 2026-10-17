# 0006. JSONL audit log + emailed PDF reports
- **Status:** Accepted (supersedes the SQLite + Streamlit dashboard of 2026-07-18)
- **Date:** 2026-09-03

## Context
Firms need evidence for compliance (ABA Opinion 512) that redaction is happening, plus a view of usage and cost. The first version used a SQLite audit database with a Streamlit admin dashboard. Reason for replacing it: **Owner to confirm.**

## Decision
Append one JSON line per request to a monthly file (`audit_YYYY_MM.jsonl`) with metadata only. Past months are gzipped and deleted after 90 days. On the 1st of each month, build a branded PDF (summary, ROI, threat breakdown, itemized ledger) and email it to the operator through Resend.

## Consequences
- Simple, append-only, no database to run or migrate. Monthly files make retention easy.
- Reports reach the firm with no dashboard to host or secure.
- The log isn't tamper-evident (no hash chain or signing), despite being described as "immutable".
- Report generation re-reads the whole month's file. Fine at current volumes.
