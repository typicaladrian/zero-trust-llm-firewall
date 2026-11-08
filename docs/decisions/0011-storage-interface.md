# 0011. Storage interface for the audit log and client vault
- **Status:** Accepted (extends 0005 and 0006; doesn't change what is stored)
- **Date:** 2026-11-08

## Context
Four places in `main.py` read and wrote local files directly: appending audit entries, reading a month for the report, the nightly gzip and 90-day prune, and loading and saving the client hash list. The project is moving to AWS Lambda, where the local disk is temporary, so this data has to move to S3. With file paths spread through the app, that would have meant editing every caller.

Alternatives: keep direct file access and change each caller later; one interface for everything; separate interfaces for audit and vault; a FastAPI dependency instead of a module-level instance.

## Decision
`zt_firewall/storage.py` defines a `Storage` protocol with five methods: `append_audit_entry`, `read_audit_entries(month)` (`None` when the month has no log), `load_client_hashes` (`None` when nothing is stored), `save_client_hashes` (replaces the whole set), and `enforce_retention`. `LocalFileStorage` is today's file behavior, moved unchanged. `storage_from_env()` picks the backend from `STORAGE_BACKEND` and raises on an unknown value. `main.py` holds the instance as `main.STORAGE`.

A `Protocol` was chosen over an abstract base class: backends and test doubles don't need to inherit anything, and the contract tests enforce behavior. A module-level instance was chosen over a FastAPI dependency because the monthly scheduler and the admin endpoint call the report function directly, where dependencies aren't resolved.

## Consequences
- An S3 backend is one new class plus a `STORAGE_BACKEND` value, with no caller changes, and it must pass the contract tests in `tests/test_storage.py`. On S3: one object per audit entry under a month prefix, written once (Object Lock); the client hash list as one object; retention through bucket lifecycle rules, so `enforce_retention` becomes a no-op. The client hash list goes in S3 rather than SSM Parameter Store, whose free tier fits only about 60 hashes.
- Tests isolate storage by swapping `main.STORAGE`. `LOG_DIR` and `VAULT_FILE` no longer exist, so an outdated patch fails loudly instead of writing somewhere unexpected.
- Saving the vault creates the storage directory if it's missing.
- Known issues outside this decision, tracked separately: the report can't read months that retention has gzipped (#21); `month` isn't validated before it's used in a path (#22); the vault file isn't written atomically (#23); on Lambda, a vault sync won't reach instances that are already running (#24).
