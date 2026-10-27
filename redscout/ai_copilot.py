"""
AI Copilot - uses local Ollama LLM. Falls back gracefully.
"""
import json
import urllib.request


class AICopilot:
    # අපි දැන් ඔබේ Qwen model එක පාවිච්චි කරමු
    def __init__(self, model: str = "qwen2.5:3b", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host

    def _available(self) -> bool:
        try:
            urllib.request.urlopen(f"{self.host}/api/tags", timeout=2)
            return True
        except Exception:
            return False

    def _ask(self, prompt: str) -> str:
        if not self._available():
            return "[AI Copilot offline - start Ollama to enable AI summaries]"
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            # Model එක run වෙන්න ටිකක් වෙලා යන නිසා timeout එක වැඩි කළා
            with urllib.request.urlopen(req, timeout=180) as resp:
                return json.loads(resp.read())["response"]
        except Exception as e:
            return f"[AI error: {e}]"

    def write_executive_summary(self, summary: dict, findings: list) -> str:
        prompt = f"""Write a 150-word executive summary for a penetration test report.
Graph summary: {summary}
Findings: {json.dumps(findings)[:3000]}
Tone: professional, non-alarmist, actionable.
"""
        return self._ask(prompt)