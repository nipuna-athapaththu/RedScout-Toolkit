"""WHOIS lookup plugin."""
import subprocess
from .base import BasePlugin

class WhoisPlugin(BasePlugin):
    name = "whois"
    technique = "whois_lookup"

    def run(self, target: str, **kwargs) -> dict:
        try:
            r = subprocess.run(["whois", target], capture_output=True, text=True, timeout=30)
            findings = []
            for line in r.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    k, v = k.strip().lower(), v.strip()
                    if k in ("registrar", "creation date", "expiry date", "org", "country"):
                        findings.append({
                            "name": f"WHOIS: {k.capitalize()}",
                            "severity": "Info",
                            "target": v,
                            "remediation": "N/A (Informational)"
                        })
            return {"target": target, "findings": findings, "raw": r.stdout}
        except FileNotFoundError:
            return {"target": target, "findings": [], "error": "whois not installed"}