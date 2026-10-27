"""Web Directory Fuzzer - Advanced."""
import requests
from .base import BasePlugin

class FuzzerPlugin(BasePlugin):
    name = "fuzzer"
    technique = "web_fuzzing"

    # තව වචන එකතු කළා
    WORDLIST = ["admin", "login", "api", "backup", "config", ".git", "robots.txt"]

    def run(self, target: str, **kwargs) -> dict:
        url = target if target.startswith("http") else f"http://{target}"
        findings = []
        
        # Soft 404 අල්ලගන්න අපි නැති page එකක ගාන බලනවා (Baseline)
        try:
            fake_url = f"{url}/this_page_doesnt_exist_12345"
            fake_resp = requests.get(fake_url, timeout=3)
            baseline_length = len(fake_resp.content)
        except Exception:
            baseline_length = 0

        for path in self.WORDLIST:
            test_url = f"{url}/{path}"
            try:
                response = requests.get(test_url, timeout=3, allow_redirects=False)
                
                # 200 ආවත්, ඒකෙ size එක baseline එකට සමාන නම් ඒක Soft 404 (බොරු page එකක්)
                is_soft_404 = (response.status_code == 200 and abs(len(response.content) - baseline_length) < 50)

                if response.status_code in [200, 403, 301, 302] and not is_soft_404:
                    findings.append({
                        "name": f"Directory/File Found: /{path}",
                        "severity": "Info" if response.status_code == 200 else "Low",
                        "target": test_url,
                        "remediation": "Review this endpoint. Ensure it does not expose sensitive data."
                    })
            except requests.exceptions.RequestException:
                continue
                
        return {"target": target, "findings": findings, "raw": "Fuzzing completed"}