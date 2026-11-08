# 0010. Load the NER model lazily, warm it at app startup
- **Status:** Accepted
- **Date:** 2026-11-08

## Context
`main.py` loaded GLiNER2 at import time. Every import paid for the model (several seconds and roughly a gigabyte of memory), including tests, which had to install a fake `gliner2` module before importing anything, and the benchmark. The planned AWS Lambda deployment makes this worse: code imported during a cold start delays the first request, and a queue worker that only needs the engine would carry the web app with it.

Alternatives: keep loading at import; load lazily with no warm-up; load lazily and warm up at startup.

## Decision
`zt_firewall/redaction/ner.py` exposes `get_model()`, wrapped in `functools.cache`. The first call imports `gliner2` and loads the model; later calls return the same instance. The redaction engine calls it when it redacts, so importing the engine costs nothing. The web app calls it in its startup event, in a worker thread, so the server still loads the model before it serves.

## Consequences
- Importing `zt_firewall.redaction.engine` loads neither the model, PyTorch, nor `main` (`tests/test_package_imports.py`).
- Production behavior is unchanged: the model loads before the first request, and a missing model still fails at startup.
- Code that times redaction must warm the model first (`evals/benchmark.py` does).
- Two threads calling `get_model()` at the same moment could each load the model once. The startup warm-up runs before any request, so this can't happen in the app. A worker that skips the warm-up would need a lock.
- Tests patch names where the engine uses them (`zt_firewall.redaction.engine`), not on `main`.
