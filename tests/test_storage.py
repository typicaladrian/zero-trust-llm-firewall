"""Storage backends (#18, step 3).

The contract tests are what every backend must pass, so a future S3 backend can be added to
the `backend` fixture and reuse them unchanged. The local tests pin the exact on-disk formats
and retention that the refactor must preserve.

Promises: P3 (client vault stores hashes only), P4 (nothing persisted holds prompt text),
P5 (metadata-only audit log). See docs/product.md.
"""
import gzip
import json
import os
import re
import time
from datetime import datetime

import pytest

from zt_firewall.storage import LocalFileStorage, storage_from_env

ENTRY = {
    "timestamp": "2026-11-08 10:00:00",
    "user": "partner@firm.test",
    "model": "claude-haiku-4-5-20251001",
    "tokens_anonymized": 3,
    "entity_breakdown": {"PERSON": 2},
    "payload_char_count": 120,
    "latency_ms": 12.5,
    "upstream_tokens": 42,
}
HASH_A, HASH_B, HASH_C = "a" * 64, "b" * 64, "c" * 64
DAY = 86400


def this_month() -> str:
    return datetime.now().strftime("%Y_%m")


@pytest.fixture(params=["local"])
def backend(request, tmp_path):
    if request.param == "local":
        return LocalFileStorage(str(tmp_path / "store"))
    raise ValueError(request.param)


# ---------------------------------------------------------------------------
# Contract: every backend
# ---------------------------------------------------------------------------

def test_contract_month_without_a_log_returns_none(backend):
    assert backend.read_audit_entries("1999_01") is None


def test_contract_appended_entries_read_back_in_order(backend):
    second = {**ENTRY, "user": "associate@firm.test"}
    backend.append_audit_entry(ENTRY)
    backend.append_audit_entry(second)
    assert backend.read_audit_entries(this_month()) == [ENTRY, second]


def test_contract_client_hashes_round_trip(backend):
    assert backend.load_client_hashes() == set()
    backend.save_client_hashes({HASH_A, HASH_B})
    assert backend.load_client_hashes() == {HASH_A, HASH_B}


def test_contract_save_replaces_the_whole_set(backend):
    backend.save_client_hashes({HASH_A, HASH_B})
    backend.save_client_hashes({HASH_C})
    assert backend.load_client_hashes() == {HASH_C}


def test_contract_retention_keeps_the_current_month_readable(backend):
    backend.append_audit_entry(ENTRY)
    backend.enforce_retention()
    assert backend.read_audit_entries(this_month()) == [ENTRY]


# ---------------------------------------------------------------------------
# Local backend: exact formats and retention (must match pre-refactor behavior)
# ---------------------------------------------------------------------------

def test_local_audit_file_name_and_line_format(tmp_path):
    LocalFileStorage(str(tmp_path)).append_audit_entry(ENTRY)
    # Compared as text: lines end "\n" on Linux (production, CI) and "\r\n" on Windows.
    assert (tmp_path / f"audit_{this_month()}.jsonl").read_text() == json.dumps(ENTRY) + "\n"


def test_local_vault_file_is_a_json_list_of_hashes_only(tmp_path):
    LocalFileStorage(str(tmp_path)).save_client_hashes({HASH_A, HASH_B})
    stored = json.loads((tmp_path / "client_hashes.json").read_text())
    assert isinstance(stored, list) and set(stored) == {HASH_A, HASH_B}
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in stored)


def test_local_backend_writes_only_inside_its_root(tmp_path):
    root = tmp_path / "store"
    store = LocalFileStorage(str(root))
    store.append_audit_entry(ENTRY)
    store.save_client_hashes({HASH_A})
    store.enforce_retention()
    assert [p.name for p in tmp_path.iterdir()] == ["store"]


def test_local_retention_gzips_past_months_and_keeps_the_current_one(tmp_path):
    old = tmp_path / "audit_2001_01.jsonl"
    old.write_text(json.dumps(ENTRY) + "\n")
    store = LocalFileStorage(str(tmp_path))
    store.append_audit_entry(ENTRY)

    store.enforce_retention()

    assert not old.exists()
    assert gzip.decompress((tmp_path / "audit_2001_01.jsonl.gz").read_bytes()).decode() == json.dumps(ENTRY) + "\n"
    assert (tmp_path / f"audit_{this_month()}.jsonl").exists()


def test_local_retention_deletes_archives_older_than_90_days(tmp_path):
    expired = tmp_path / "audit_2001_01.jsonl.gz"
    recent = tmp_path / "audit_2001_02.jsonl.gz"
    for path, age_days in ((expired, 91), (recent, 89)):
        path.write_bytes(gzip.compress(b"{}\n"))
        stamp = time.time() - age_days * DAY
        os.utime(path, (stamp, stamp))

    LocalFileStorage(str(tmp_path)).enforce_retention()

    assert not expired.exists()
    assert recent.exists()


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def test_default_backend_is_local_files_in_audit_log_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)
    monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path))
    store = storage_from_env()
    assert isinstance(store, LocalFileStorage)
    assert store.root == str(tmp_path)


def test_unknown_backend_fails_closed(monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "dropbox")
    with pytest.raises(ValueError, match="dropbox"):
        storage_from_env()
