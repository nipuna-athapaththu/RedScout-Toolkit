"""Example Nmap plugin (safe: -sV only, no aggressive scripts)."""
import subprocess
from .base import BasePlugin


class NmapPlugin(BasePlugin):
    name = "nmap"
    technique = "port_scan"

    def run(self, target: str, ports: str = "1-1000", **kwargs) -> dict:
        cmd = ["nmap", "-sV", "-T4", "-Pn", "-p", ports, target]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            return {
                "target": target,
                "findings": self._parse(result.stdout),
                "raw": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        except FileNotFoundError:
            return {"target": target, "findings": [], "raw": "", "error": "nmap not installed on system"}
        except subprocess.TimeoutExpired:
            return {"target": target, "findings": [], "raw": "", "error": "timeout"}

    def _parse(self, output: str):
        findings = []
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                findings.append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2] if len(parts) > 2 else "",
                    "version": " ".join(parts[3:]) if len(parts) > 3 else "",
                })
        return findings