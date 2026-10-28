# 🎯 RedScout

**Mobile-First Ethical Red Team Orchestration Framework**

[![CI](https://github.com/nipuna-athapaththu/RedScout-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/nipuna-athapaththu/RedScout-Toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

RedScout is a modular, CLI-based penetration testing framework designed for ethical red teaming. It automates reconnaissance, web vulnerability scanning, and custom payload injection while strictly enforcing authorization boundaries. It features a local AI copilot for automated report generation, ensuring 100% data privacy.

---

# 🛡️ Technical Architecture & Workflow Deep Dive

RedScout follows a strict **Pipeline Architecture**: `Input Validation` → `Dynamic Plugin Execution` → `Data Processing` → `Secure Storage` → `Automated Reporting`. Here is how the system operates under the hood:

### ⚙️ Phase 1: Initialization & Ethical Guardrails (The Entry Point)
When a command is executed, the framework builds its defense layers:
1. **CLI Parsing (Typer):** The `main.py` core utilizes the `Typer` library to parse incoming command-line arguments and flags dynamically.
2. **Auto-Scope Generation:** If no predefined YAML scope file (`-s`) is provided, a temporary scope is generated. It uses Python's `datetime` to build a 1-hour validity window and `urllib.parse` to extract the base domain (`netloc`). The domain name is sanitized using RegEx to enforce cross-platform compatibility, preventing breaking operations on Windows OS due to forbidden characters.
3. **Scope Guard Validation:** The `ScopeGuard` module parses permissions via `PyYAML`, checking two critical vectors:
   * *Temporal Validity:* Validates if the current UTC time is tightly locked between the `valid_from` and `valid_until` windows.
   * *Target Authorization:* Leverages Python’s `ipaddress` module to mathematically verify if the target falls within an authorized CIDR range or strictly matches the domain.
   * *Bypass Mode:* If `--no-scope` is explicitly passed, a `DummyGuard` class instantiates to bypass security rules while echoing terminal-wide alerts.

### 🧩 Phase 2: Orchestration & Dynamic Execution (The Brain)
1. **Dynamic Plugin Discovery:** Inside `registry.py`, the system relies on Python's native `pkgutil` and `importlib` modules to programmatically scan the `plugins/` directory. It discovers all classes inheriting from `BasePlugin` and registers them automatically at runtime.
2. **Parallel Execution (Concurrency):** To optimize performance, `main.py` deploys `concurrent.futures.ThreadPoolExecutor` to handle concurrent scanning operations.
   * *Engineering Note:* While highly effective for minimizing overhead during **I/O-bound operations** (HTTP requests/Nmap scripting subprocesses), it respects Python's **Global Interpreter Lock (GIL)** constraints and targets async migration as a future goal.

### 🎯 Phase 3: Active Scanning (The Plugins)
Plugins act as standardized extensions that consistently output structured JSON structures:
1. **Injection Plugin (XSS/SQLi):** Parsed query parameters from `urllib.parse` are loaded with context-aware strings. The execution utilizes the `requests` library to intercept raw HTTP streams, scanning for raw reflections (Reflected XSS) or database engine signature matches (Error-based SQLi).
2. **Web Scanner:** Inspects response headers via `requests` to map structural misconfigurations (missing HSTS, CSP, or X-Frame-Options policies).
3. **Nuclei Integration:** Runs native binary targets asynchronously using Python's `subprocess` module. It feeds native execution outputs into a live **JSONL stream** (`-jsonl`), which is parsed dynamically line-by-line via `json.loads()`.

### 📊 Phase 4: Data Processing & AI Analysis (The Analyst)
1. **Attack Graph Engine:** Uses the `NetworkX` library to ingest vulnerabilities into a Directed Graph model (`nx.DiGraph`). Nodes represent `Hosts`, `Services`, and `Vulnerabilities`, while edges define logical vectors (e.g., `Host -> exposes -> Service -> has_vuln -> XSS`).
2. **AI Copilot Integration:** Aggregates findings and makes standard POST requests using `urllib.request` to a local **Ollama API** running the Qwen 2.5 architecture. Structured system prompt restrictions enforce local, non-alarmist executive generation. If offline, the loop utilizes graceful exceptions (`try/except`) to provide fallback diagnostics without interrupting the pipeline.

### 🔐 Phase 5: Evidence Storage & Reporting (The Output)
1. **Encrypted Evidence Vault:** The final output is encrypted via `cryptography.fernet` using strong symmetric **AES keys**.
   * *Chain of Custody:* Implements a cryptographically locked Hash Chain. Each block computes a `SHA-256` hash derived from `previous_hash + current_entry_data`, ensuring absolute data integrity.
2. **PDF Report Generation:** The `pdf_report.py` file maps results to the **MITRE ATT&CK** matrix and dynamically calculates strict **CVSS v3.1** scores. The data is rendered to HTML template code and converted into standard vector documents via `WeasyPrint`.

---

## ✨ Key Features

- 🔒 **Scope Guard:** Cryptographically enforced authorization via YAML. Includes an Auto-Scope generator for safe, time-limited quick scans.
- ⚡ **Parallel Execution:** Multithreaded architecture using `ThreadPoolExecutor` to run multiple plugins simultaneously.
- 🎯 **Custom Injection Engine:** Tests for Reflected XSS and Error-based SQL Injection with context-aware payloads.
- 🧠 **Local AI Copilot:** Integrates with Local LLMs (Ollama/Qwen) to automatically write professional Executive Summaries.
- 🔐 **Encrypted Evidence Vault:** AES encryption + SHA-256 hash-chain for forensic integrity (Chain of Custody).
- 📊 **Automated Reporting:** Generates professional PDF/HTML reports mapped to **CVSS v3.1** and **MITRE ATT&CK**.
- 🖥️ **Web Dashboard:** FastAPI-based local dashboard to monitor scan history and audit logs in real-time.
- 🔌 **Plugin Architecture:** Extensible SDK to easily drop in new Python-based security tools.

---

## 🚀 Installation & Usage Guide

### 1. Prerequisites
Ensure you have the following installed:
- **Python 3.10+**
- **Nmap** (Optional, required for `nmap` plugin)
- **Nuclei** (Optional, download `nuclei.exe` and place it in the root folder)
- **Ollama** (Optional, run `ollama run qwen2.5:3b` to enable AI summaries)

### 2. Installation
```bash
# 1. Clone the repository
git clone https://github.com/nipuna-athapaththu/RedScout-Toolkit.git
cd RedScout-Toolkit

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate the virtual environment
# On Windows:
.\.venv\Scripts\activate
# On Mac/Linux:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

### 3. Running a Scan
**Fast Scan (Auto-Scope):** No manual YAML needed for quick, authorized tests.
```bash
python -m redscout.main scan -t "http://webappsecurity.com" --only web_scanner,injection
```

**Full Scan:** Runs all available plugins.
```bash
python -m redscout.main scan -t "http://testfire.net"
```

**Real-World Client Scan:** Use a signed YAML scope file for strict compliance.
```bash
python -m redscout.main scan -s scopes/client_scope.yaml -t "192.168.1.100"
```

**Bypass Mode (Developer use only):**
```bash
python -m redscout.main scan -t "http://testfire.net" --no-scope
```

### 4. Web Dashboard
To launch the local dashboard to view encrypted vault logs and audit history:
```bash
python -m redscout.main dashboard
```
*Then open `http://localhost:8000` in your browser.*

---

## 🚧 Known Limitations & Future Roadmap

1. **Concurrency (GIL Limitation):** Currently uses `ThreadPoolExecutor`.
   * *Future:* Migrate the core network layer to `asyncio` and `httpx` for massive concurrent request handling.
2. **Pre-flight Validation (WAF Detection):** Active plugins send payloads directly.
   * *Future:* Implement a `Pre-flight` module to detect Web Application Firewalls (WAF) before running active attacks.
3. **Context-Aware False Positives:** The XSS scanner checks for payload reflection but doesn't verify executable context.
   * *Future:* Integrate AI to perform context-aware analysis of response snippets to eliminate false positives.

---

## ⚠️ Ethical Disclaimer

**RedScout is designed for authorized security testing and educational purposes only.** 
You must have explicit, written permission to test any target. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Unauthorized use against public infrastructure is illegal and strictly prohibited.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
