"""Nuclei plugin - Advanced Web Vulnerability Scanner."""
import json
import subprocess
import os
from .base import BasePlugin

class NucleiPlugin(BasePlugin):
    name = "nuclei"
    technique = "web_vuln_scan"

    def run(self, target: str, **kwargs) -> dict:
        url = target if target.startswith("http") else f"http://{target}"
        
        # Windows වලට නම් nuclei.exe දෙන්න ඕන
        nuclei_cmd = ".\\nuclei.exe" if os.name == "nt" else "nuclei"
        
        cmd = [nuclei_cmd, "-u", url, "-severity", "low,medium,high,critical", "-jsonl", "-silent", "-no-interactsh"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            findings = []
            for line in result.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    findings.append({
                        "name": obj.get("info", {}).get("name", "Nuclei Finding"),
                        "severity": obj.get("info", {}).get("severity", "medium"),
                        "target": obj.get("matched-at", url),
                        "remediation": obj.get("info", {}).get("description", "Review and patch the vulnerability.")
                    })
                except json.JSONDecodeError:
                    continue
            return {"target": target, "findings": findings, "raw": result.stdout}
        except FileNotFoundError:
            return {"target": target, "findings": [], "error": "nuclei.exe not found in folder"}
        except subprocess.TimeoutExpired:
            return {"target": target, "findings": [], "error": "timeout"}