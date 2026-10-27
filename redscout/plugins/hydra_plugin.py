"""Hydra plugin - authorized credential testing only."""
import re
import subprocess
from .base import BasePlugin


class HydraPlugin(BasePlugin):
    name = "hydra"
    technique = "credential_bruteforce"

    def run(self, target: str, service: str = "ssh", userlist: str = None,
            passlist: str = None, **kwargs) -> dict:
        if not userlist or not passlist:
            return {"target": target, "findings": [], "error": "userlist/passlist required"}

        cmd = [
            "hydra", "-L", userlist, "-P", passlist,
            "-f", "-t", "4", "-o", "/tmp/hydra_out.txt",
            f"{service}://{target}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            findings = self._parse("/tmp/hydra_out.txt")
            return {"target": target, "findings": findings, "raw": result.stdout}
        except FileNotFoundError:
            return {"target": target, "findings": [], "error": "hydra not installed"}
        except subprocess.TimeoutExpired:
            return {"target": target, "findings": [], "error": "timeout"}

    def _parse(self, path):
        findings = []
        try:
            for line in open(path):
                m = re.match(r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)", line)
                if m:
                    findings.append({
                        "port": m.group(1),
                        "service": m.group(2),
                        "host": m.group(3),
                        "login": m.group(4),
                        "password": "***REDACTED***",
                    })
        except FileNotFoundError:
            pass
        return findings