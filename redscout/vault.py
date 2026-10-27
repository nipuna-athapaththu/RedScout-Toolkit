"""
Evidence Vault - encrypts findings, logs, screenshots with AES-256 (Fernet).
Each evidence entry is hash-chained for tamper detection.
"""
import json
import hashlib
import datetime
from pathlib import Path
from cryptography.fernet import Fernet


class EvidenceVault:
    def __init__(self, vault_dir: str = "vault"):
        self.dir = Path(vault_dir)
        self.dir.mkdir(exist_ok=True)
        self.key_file = self.dir / ".vault_key"
        self.data_file = self.dir / "evidence.enc"
        self.index_file = self.dir / "index.json"
        self._load_or_create_key()
        self.index = json.loads(self.index_file.read_text()) if self.index_file.exists() else []

    def _load_or_create_key(self):
        if self.key_file.exists():
            key = self.key_file.read_bytes()
        else:
            key = Fernet.generate_key()
            self.key_file.write_bytes(key)
            # Windows එකේ chmod වැඩ නොකරන නිසා try-except දාලා තියෙනවා
            try:
                self.key_file.chmod(0o600)
            except Exception:
                pass
        self.fernet = Fernet(key)

    def _load_entries(self):
        if not self.data_file.exists():
            return []
        raw = self.fernet.decrypt(self.data_file.read_bytes())
        return json.loads(raw)

    def _save_entries(self, entries):
        raw = json.dumps(entries).encode()
        self.data_file.write_bytes(self.fernet.encrypt(raw))

    def add(self, category: str, target: str, payload, notes: str = ""):
        entries = self._load_entries()
        prev_hash = entries[-1]["hash"] if entries else "0" * 64
        entry = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "category": category,
            "target": target,
            "payload": payload,
            "notes": notes,
            "prev_hash": prev_hash,
        }
        entry["hash"] = hashlib.sha256(
            (prev_hash + json.dumps(entry, sort_keys=True)).encode()
        ).hexdigest()
        entries.append(entry)
        self._save_entries(entries)
        self.index.append({"ts": entry["ts"], "category": category, "target": target})
        self.index_file.write_text(json.dumps(self.index, indent=2))
        return entry["hash"]

    def verify_chain(self) -> bool:
        entries = self._load_entries()
        prev = "0" * 64
        for e in entries:
            if e["prev_hash"] != prev:
                return False
            expected = hashlib.sha256(
                (prev + json.dumps({k: v for k, v in e.items() if k != "hash"}, sort_keys=True)).encode()
            ).hexdigest()
            if e["hash"] != expected:
                return False
            prev = e["hash"]
        return True