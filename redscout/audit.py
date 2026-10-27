"""
Immutable-ish audit log (append-only, hash-chained).
"""
import hashlib
import json
import datetime
from pathlib import Path


class AuditLog:
    def __init__(self, path: str = "audit.log"):
        self.path = Path(path)
        self._last_hash = "0" * 64
        if self.path.exists():
            lines = self.path.read_text().strip().splitlines()
            if lines:
                last = json.loads(lines[-1])
                self._last_hash = last["hash"]

    def _hash(self, payload: dict) -> str:
        data = json.dumps(payload, sort_keys=True).encode()
        return hashlib.sha256(self._last_hash.encode() + data).hexdigest()

    def log(self, event: str, **kwargs):
        entry = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event,
            "prev_hash": self._last_hash,
            **kwargs,
        }
        entry["hash"] = self._hash(entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        self._last_hash = entry["hash"]