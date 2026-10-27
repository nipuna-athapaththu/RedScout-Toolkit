"""Lightweight local dashboard."""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pathlib import Path
import json

app = FastAPI(title="RedScout Dashboard")

INDEX = """<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RedScout</title>
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
<style>
body {{ font-family: system-ui; background:#0d1117; color:#c9d1d9; margin:16px; }}
h1 {{ color:#58a6ff; }}
.card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; margin:12px 0; }}
.badge {{ padding:2px 8px; border-radius:4px; background:#238636; color:#fff; font-size:12px; }}
</style></head><body>
<h1>🎯 RedScout Dashboard</h1>
<div class="card">
  <h3>Vault Index</h3>
  <div hx-get="/vault" hx-trigger="load" hx-swap="innerHTML">Loading...</div>
</div>
<div class="card">
  <h3>Audit Log (last 20)</h3>
  <div hx-get="/audit" hx-trigger="load" hx-swap="innerHTML">Loading...</div>
</div>
</body></html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX


@app.get("/vault", response_class=HTMLResponse)
def vault():
    idx = Path("vault/index.json")
    if not idx.exists():
        return "<i>No vault entries yet.</i>"
    entries = json.loads(idx.read_text())[-20:]
    rows = "".join(
        f"<div><span class='badge'>{e['category']}</span> {e['target']} <small>{e['ts']}</small></div>"
        for e in entries
    )
    return rows or "<i>Empty.</i>"


@app.get("/audit", response_class=HTMLResponse)
def audit():
    p = Path("audit.log")
    if not p.exists():
        return "<i>No audit log.</i>"
    lines = p.read_text().strip().splitlines()[-20:]
    out = ""
    for line in lines:
        obj = json.loads(line)
        out += f"<div><b>{obj['event']}</b> <small>{obj['ts']}</small></div>"
    return out