"""DNS enumeration (A, MX, TXT, NS)."""
import subprocess
from .base import BasePlugin

class DNSPlugin(BasePlugin):
    name = "dns"
    technique = "dns_enum"
    RECORD_TYPES = ["A", "MX", "TXT", "NS"]

    def run(self, target: str, **kwargs) -> dict:
        findings = []
        for rt in self.RECORD_TYPES:
            try:
                r = subprocess.run(["dig", "+short", rt, target], capture_output=True, text=True, timeout=10)
                for line in r.stdout.splitlines():
                    if line.strip():
                        findings.append({
                            "name": f"DNS Record ({rt})",
                            "severity": "Info",
                            "target": line.strip(),
                            "remediation": "Ensure DNS records are intended to be public."
                        })
            except FileNotFoundError:
                return {"target": target, "findings": [], "error": "dig not installed"}
        return {"target": target, "findings": findings, "raw": ""}