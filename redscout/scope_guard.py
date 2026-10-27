"""
Scope Guard - enforces authorized targets, time windows, and techniques.
"""
import yaml
import ipaddress
import datetime
from pathlib import Path


class ScopeError(Exception):
    pass


class ScopeGuard:
    def __init__(self, scope_file: str):
        self.scope_file = Path(scope_file)
        if not self.scope_file.exists():
            raise ScopeError(f"Scope file not found: {scope_file}")
        with open(self.scope_file) as f:
            self.scope = yaml.safe_load(f)
        self._validate_scope()

    def _validate_scope(self):
        required = ["authorized_by", "valid_from", "valid_until", "targets"]
        for key in required:
            if key not in self.scope:
                raise ScopeError(f"Missing required scope field: {key}")

    def _now(self):
        return datetime.datetime.now(datetime.timezone.utc)

    def _parse_dt(self, s):
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))

    def check_time_window(self):
        now = self._now()
        start = self._parse_dt(self.scope["valid_from"])
        end = self._parse_dt(self.scope["valid_until"])
        if not (start <= now <= end):
            raise ScopeError(
                f"Out of authorized time window: {start} -> {end}"
            )

    def check_target(self, target: str) -> bool:
        """Raise ScopeError if target not authorized."""
        self.check_time_window()

        for entry in self.scope["targets"]:
            # 1. ඉස්සෙල්ලම හරියටම ගැලපෙනවද බලන්න (URLs, domains, single IPs)
            if entry == target:
                return True
                
            # 2. ඊට පස්සේ CIDR (IP Range) එකක්ද බලන්න
            if "/" in entry:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    ip = ipaddress.ip_address(target)
                    if ip in net:
                        return True
                except ValueError:
                    pass # IP එකක් නෙවෙයි නම් මොකුත් කරන්නේ නෑ

        raise ScopeError(f"Target NOT in authorized scope: {target}")

    def allowed_techniques(self):
        return self.scope.get("allowed_techniques", [])

    def is_technique_allowed(self, technique: str) -> bool:
        allowed = self.allowed_techniques()
        if not allowed:
            return False
        return technique in allowed