"""
Notifier - sends alerts to Slack/Discord/Telegram webhooks.
"""
import json
import urllib.request
from pathlib import Path
import yaml


class Notifier:
    def __init__(self, config_path: str = ".env.example"):
        self.config = {}
        env = Path(".env")
        if env.exists():
            for line in env.read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    self.config[k.strip()] = v.strip()

    def _post(self, url: str, payload: dict):
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception:
            return False

    def slack(self, text: str):
        url = self.config.get("SLACK_WEBHOOK")
        if url:
            return self._post(url, {"text": text})
        return False

    def discord(self, text: str):
        url = self.config.get("DISCORD_WEBHOOK")
        if url:
            return self._post(url, {"content": text})
        return False

    def telegram(self, text: str):
        token = self.config.get("TELEGRAM_BOT_TOKEN")
        chat = self.config.get("TELEGRAM_CHAT_ID")
        if token and chat:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            return self._post(url, {"chat_id": chat, "text": text})
        return False

    def broadcast(self, text: str):
        results = {
            "slack": self.slack(text),
            "discord": self.discord(text),
            "telegram": self.telegram(text),
        }
        return results
    