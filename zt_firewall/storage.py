"""Persistent storage for the audit log and the hashed client list, behind one interface.

Callers depend on the Storage protocol; STORAGE_BACKEND picks the implementation. Only the
local-file backend exists today. The AWS deployment adds an S3 backend that implements the
same five methods and must pass the contract tests in tests/test_storage.py (decision 0011).
"""
import glob
import gzip
import json
import os
import shutil
import time
from datetime import datetime
from typing import Protocol

AUDIT_RETENTION_DAYS = 90


class Storage(Protocol):
    def append_audit_entry(self, entry: dict) -> None:
        """Append one metadata-only audit entry to the current month's log."""

    def read_audit_entries(self, month: str) -> list[dict] | None:
        """Return the entries for month "YYYY_MM" in write order, or None if it has no log.

        Entries are returned as parsed, not validated; a malformed log raises or yields
        non-dict values, and the report turns either into a 500.
        """

    def load_client_hashes(self) -> set[str] | None:
        """Return the stored client hashes, or None if nothing has been stored."""

    def save_client_hashes(self, hashes: set[str]) -> None:
        """Replace the stored client hashes with exactly this set (hashes only, never names)."""

    def enforce_retention(self) -> None:
        """Apply the audit log retention policy (compress past months, delete after 90 days)."""


class LocalFileStorage:
    """Monthly JSONL audit files and a JSON client-hash file in one directory.

    In production the directory is the proxy-audit-logs Docker volume (/app/logs).
    """

    def __init__(self, root: str):
        self.root = root
        self.vault_file = os.path.join(root, "client_hashes.json")

    def _audit_path(self, month: str) -> str:
        return os.path.join(self.root, f"audit_{month}.jsonl")

    def append_audit_entry(self, entry: dict) -> None:
        os.makedirs(self.root, exist_ok=True)
        current_month = datetime.now().strftime("%Y_%m")
        with open(self._audit_path(current_month), "a") as f:
            f.write(json.dumps(entry) + "\n")

    def read_audit_entries(self, month: str) -> list[dict] | None:
        path = self._audit_path(month)
        if not os.path.exists(path):
            return None
        with open(path, "r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def load_client_hashes(self) -> set[str] | None:
        if not os.path.exists(self.vault_file):
            return None
        with open(self.vault_file, "r") as f:
            return set(json.load(f))

    def save_client_hashes(self, hashes: set[str]) -> None:
        os.makedirs(self.root, exist_ok=True)
        with open(self.vault_file, "w") as f:
            json.dump(list(hashes), f)

    def enforce_retention(self) -> None:
        os.makedirs(self.root, exist_ok=True)
        current_month = datetime.now().strftime("%Y_%m")

        # 1. Compress previous months' JSONL files
        for filepath in glob.glob(f"{self.root}/audit_*.jsonl"):
            if current_month not in os.path.basename(filepath):
                with open(filepath, "rb") as f_in:
                    with gzip.open(f"{filepath}.gz", "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove(filepath)

        # 2. Delete archives older than the retention period
        cutoff_time = time.time() - AUDIT_RETENTION_DAYS * 86400
        for filepath in glob.glob(f"{self.root}/audit_*.gz"):
            if os.path.getmtime(filepath) < cutoff_time:
                os.remove(filepath)


def storage_from_env() -> Storage:
    """Build the storage backend named by STORAGE_BACKEND (default "local")."""
    backend = os.getenv("STORAGE_BACKEND", "local")
    if backend == "local":
        return LocalFileStorage(os.getenv("AUDIT_LOG_DIR", "/app/logs"))
    raise ValueError(f"Unknown STORAGE_BACKEND {backend!r}; expected 'local'")
