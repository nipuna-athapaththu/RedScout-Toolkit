"""Custom Payload Injector for SQLi and XSS (Educational/Authorized only)."""
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import BasePlugin

class InjectionPlugin(BasePlugin):
    name = "injection"
    technique = "web_vuln_scan"  # අපි මේක web_vuln_scan එකටම map කරමු

    # අපි යවන පරීක්ෂණ Payloads
    SQLI_PAYLOADS = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --"]
    XSS_PAYLOADS = ["<script>alert('XSS')</script>", "\"><script>alert(1)</script>"]

    def run(self, target: str, **kwargs) -> dict:
        url = target if target.startswith("http") else f"http://{target}"
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        findings = []

        # Target එකේ parameters නැත්නම් (උදා: ?id=1), අපිට inject කරන්න බෑ
        if not query_params:
            return {"target": target, "findings": [], "raw": "No URL parameters found for injection"}

        # SQL Injection පරීක්ෂාව
        for payload in self.SQLI_PAYLOADS:
            test_params = {k: payload for k in query_params.keys()}
            test_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=test_query))
            
            try:
                r = requests.get(test_url, timeout=5)
                # සරල ලකුණු: SQL error එකක් ආවොත්
                sql_errors = ["SQL syntax", "mysql_fetch", "ORA-01756", "PostgreSQL query failed"]
                if any(err.lower() in r.text.lower() for err in sql_errors):
                    findings.append({
                        "name": f"Potential SQL Injection ({payload})",
                        "severity": "High",
                        "target": test_url,
                        "remediation": "Use parameterized queries or prepared statements."
                    })
                    break  # එකක් හම්බුනා නම් ඉතුරු ඒවා එවන්න ඕන නෑ
            except requests.RequestException:
                pass

        # XSS පරීක්ෂාව
        for payload in self.XSS_PAYLOADS:
            test_params = {k: payload for k in query_params.keys()}
            test_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=test_query))
            
            try:
                r = requests.get(test_url, timeout=5)
                # Payload එක response එකේ එහෙමම ආවොත් (Reflected XSS)
                if payload in r.text:
                    findings.append({
                        "name": f"Potential Reflected XSS",
                        "severity": "Medium",
                        "target": test_url,
                        "remediation": "Sanitize and encode user inputs before reflecting them in HTML."
                    })
                    break
            except requests.RequestException:
                pass

        return {"target": target, "findings": findings, "raw": "Injection testing complete"}