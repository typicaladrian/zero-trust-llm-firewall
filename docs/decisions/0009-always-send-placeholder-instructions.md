# 0009. Always send the placeholder instructions as their own system message
- **Status:** Accepted
- **Date:** 2026-10-20

## Context
`SYSTEM_PROMPT` tells the model to keep `[LABEL_N]` placeholders intact, which restoring the response (P6) depends on. It was inserted only when the conversation had no system message, so any client system prompt (an Open WebUI preset, injected document context) silently dropped it. Client system messages also skipped redaction (#4). Once they are redacted, they carry placeholders too, so the model needs the instructions in every conversation.

Alternatives: merge the instructions into the client's system message, or keep sending them only when there is none.

## Decision
Redact system messages like every other role, with the same per-request vault. Always insert a copy of `SYSTEM_PROMPT` at index 0, after redaction, so it is never redacted itself. The client's messages follow unchanged apart from placeholders, so the firm's own instructions are the last system text the model reads. `SYSTEM_PROMPT` covers placeholder handling only and sets no persona ("You are a helpful AI assistant" was removed), so it doesn't compete with the firm's.

## Consequences
- A conversation with a client system prompt now has two system messages. OpenAI accepts this. LiteLLM turns them into two ordered system blocks for Anthropic. A provider that allows only one system message would need the merge alternative.
- The client's text is never rewritten, and restoring each message with the vault gives back exactly what the client sent (`test_redaction_round_trip_loses_no_context`).
- Large system content (presets, RAG context) is redacted again on every turn, adding latency (decision 0003). Audit entity counts include system-message entities.
