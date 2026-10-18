# 0004. No streaming in the zero-trust lane
- **Status:** Accepted
- **Date:** 2026-09 (introduced with the public research lane)

## Context
Open WebUI asks for streamed responses by default. In a stream, a placeholder like `[PERSON_12]` can be split across chunks (`[PERS` + `ON_12]`), so restoring chunk by chunk would leak placeholders or mangle the text.

## Decision
Force `stream=False` for redacted requests: get the whole response, restore it, then return it. Only the unredacted `public-research-base` lane streams.

## Consequences
- Restoration is correct and simple.
- Associates wait for the full response before seeing anything. Streaming with a buffer that holds back partial placeholders is a possible future improvement.
