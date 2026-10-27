"""Web Security Headers Scanner."""
import requests
from .base import BasePlugin


class WebScannerPlugin(BasePlugin):
    name = "web_scanner"
    technique = "web_vuln_scan"

    REQUIRED_HEADERS = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
    ]

    def run(self, target: str, **kwargs) -> dict:
        # URLif not provided, prepend http:// to the target 
        url = target if target.startswith("http") else f"http://{target}"
        findings = []
        
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            for header in self.REQUIRED_HEADERS:
                if header not in headers:
                    findings.append({
                        "name": f"Missing Security Header: {header}",
                        "severity": "Medium",
                        "url": url,
                        "remediation": f"Add the '{header}' header to server responses."
                    })
            
            return {"target": target, "findings": findings, "raw": f"HTTP Status: {response.status_code}"}
            
        except requests.exceptions.RequestException as e:
            return {"target": target, "findings": [], "error": str(e)}