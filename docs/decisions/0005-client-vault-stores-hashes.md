# 0005. Client vault stores hashes only
- **Status:** Accepted, with a known weakness to fix
- **Date:** 2026-08-20

## Context
Firms need certain names (clients, opposing parties, their own name) always redacted, even when the NER model doesn't see them as entities. Storing that list in plain text on the appliance would itself be a confidentiality risk.

## Decision
`POST /v1/vault/sync` normalizes each name (lowercase, alphanumeric only), stores only its SHA-256 hash in `/app/logs/client_hashes.json`, and keeps the set in memory. During redaction, every 1–5-word n-gram is hashed the same way and checked against the set.

## Consequences
- The appliance never stores the client list in plain text.
- **Weakness:** the hashes are unsalted, and names are guessable, so someone holding the hash file could hash a list of likely names (law-firm directories, court records) and recover matches. A keyed hash (HMAC with a per-appliance secret) would close this. Until then, the marketing claim "irreversible" overstates the protection.
- N-gram hashing is O(words × 5) per chunk, which is cheap next to NER.
