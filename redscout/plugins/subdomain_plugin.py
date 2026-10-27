"""Subdomain enumeration via DNS resolution."""
import socket
from .base import BasePlugin

DEFAULT_WORDLIST = ["www", "mail", "ftp", "admin", "api", "dev"]

class SubdomainPlugin(BasePlugin):
    name = "subdomain"
    technique = "subdomain_enum"

    def run(self, target: str, **kwargs) -> dict:
        findings = []
        for word in DEFAULT_WORDLIST:
            fqdn = f"{word}.{target}"
            try:
                ip = socket.gethostbyname(fqdn)
                findings.append({
                    "name": f"Subdomain Found: {word}",
                    "severity": "Info",
                    "target": ip,
                    "remediation": "Review if this subdomain should be publicly accessible."
                })
            except socket.gaierror:
                continue
        return {"target": target, "findings": findings, "raw": ""}