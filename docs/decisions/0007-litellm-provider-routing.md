# 0007. LiteLLM for provider routing
- **Status:** Accepted
- **Date:** 2026-07-27

## Context
Firms bring their own API keys and may use Anthropic, OpenAI or both. Open WebUI speaks the OpenAI API format.

## Decision
The proxy exposes an OpenAI-compatible API and forwards to providers through LiteLLM, which converts the format and picks credentials from standard environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`).

## Consequences
- Adding a provider or model is mostly configuration (the `/v1/models` list plus a key).
- Model IDs exposed to Open WebUI must be valid LiteLLM names.
- LiteLLM is a large, fast-moving dependency, so pin it and check updates against the eval suite.
