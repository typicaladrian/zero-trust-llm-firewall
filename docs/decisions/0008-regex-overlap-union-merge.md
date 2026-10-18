# 0008. Merge overlapping regex matches into their union
- **Status:** Accepted
- **Date:** 2026-10-18

## Context
Step 0 replaced every `REGEX_PATTERNS` match from the end of the text backward, but it never removed overlaps first. When two patterns matched overlapping spans, the second splice used offsets the first had already shifted. Text was mangled, fragments leaked (a ZIP code in the reproducing case), and restoring the response gave the wrong text (#6).

The vault and NER layers already de-overlap with "leftmost wins; at the same start, longest wins", which drops every later match that overlaps a kept one. For regex that rule leaks: when two spans only partly overlap, the dropped span's tail is left in plain text. Regex patterns are the high-precision safety net, so every character any of them matched should stay covered.

## Decision
Before replacing, merge overlapping regex spans (`start < previous end`) into one span covering their union. The merged span takes the label of its longest member; ties go to `REGEX_PATTERNS` order. Spans that only touch stay separate. The vault and NER layers keep their own rule.

## Consequences
- No character a regex pattern matched reaches the LLM, and redact → restore is exact.
- One token can stand for text that more than one pattern matched. Audit and PDF category counts then show only the winning label. In the #6 case a card number followed by a US address counts as one `ADDRESS_(US)` rather than a card plus an address.
- A chain of overlapping matches becomes one large token, which can over-redact. The US-address pattern pulling in a preceding number is a precision problem in that pattern, not in the merge.
