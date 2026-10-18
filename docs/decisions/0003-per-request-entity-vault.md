# 0003. Per-request in-memory entity vault
- **Status:** Accepted
- **Date:** 2026-07-17

## Context
To restore the LLM's answer into plain text, the proxy has to remember which placeholder stands for which original value. Storing that mapping would create exactly the plaintext record of client data the product promises doesn't exist.

## Decision
Create a new `EntityVault` for each HTTP request. It holds the placeholder ↔ value maps in memory only and is discarded when the request ends. Multi-turn chats work because Open WebUI resends the full history, so the whole conversation is re-redacted under one vault each time.

## Consequences
- No original values are written to disk, which backs the "zero plaintext persistence" promise.
- Placeholder numbers can change between requests. That's harmless, because the model only ever sees one request's numbering.
- The full history is re-redacted on every turn, so the cost grows with conversation length.
