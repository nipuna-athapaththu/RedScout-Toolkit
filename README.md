# 🎯 RedScout

**Mobile-First Ethical Red Team Orchestration Framework**

[![CI](https://github.com/nipuna-athapaththu/RedScout-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/nipuna-athapaththu/RedScout-Toolkit/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

RedScout is a modular, CLI-based penetration testing framework designed for ethical red teaming. It automates reconnaissance, web vulnerability scanning, and custom payload injection while strictly enforcing authorization boundaries. It features a local AI copilot for automated report generation, ensuring 100% data privacy.

## ✨ Key Features

- 🔒 **Scope Guard:** Cryptographically enforced authorization via YAML. Includes an Auto-Scope generator for safe, time-limited quick scans.
- ⚡ **Parallel Execution:** Multithreaded architecture using `ThreadPoolExecutor` to run multiple plugins (Nmap, Fuzzer, Injection) simultaneously.
- 🎯 **Custom Injection Engine:** Tests for Reflected XSS and Error-based SQL Injection with context-aware payloads.
- 🧠 **Local AI Copilot:** Integrates with Local LLMs (Ollama/Qwen) to automatically write professional Executive Summaries.
- 🔐 **Encrypted Evidence Vault:** AES-256 encryption + SHA-256 hash-chain for forensic integrity (Chain of Custody).
- 📊 **Automated Reporting:** Generates professional PDF/HTML reports mapped to **CVSS v3.1** and **MITRE ATT&CK**.
- 🖥️ **Web Dashboard:** FastAPI-based local dashboard to monitor scan history and audit logs in real-time.
- 🔌 **Plugin Architecture:** Extensible SDK to easily drop in new Python-based security tools.

## 🚀 Installation & Usage Guide

Follow these steps to set up and run RedScout on your local machine.

### 1. Prerequisites
Ensure you have the following installed:
- **Python 3.10+**
- **Nmap** (Optional, required for `nmap` plugin)
- **Nuclei** (Optional, download `nuclei.exe` and place it in the root folder for CVE scanning)
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
3. Running a Scan
Fast Scan (Auto-Scope): No manual YAML needed for quick, authorized tests. Runs specific plugins for speed.

bash
python -m redscout.main scan -t "http://testfire.net" --only web_scanner,injection
Full Scan: Runs all available plugins.

bash
python -m redscout.main scan -t "http://testfire.net"
Real-World Client Scan: Use a signed YAML scope file for strict compliance.

bash
python -m redscout.main scan -s scopes/client_scope.yaml -t "192.168.1.100"
Bypass Mode (Developer use only):

bash
python -m redscout.main scan -t "http://testfire.net" --no-scope
4. Web Dashboard
To launch the local dashboard to view encrypted vault logs and audit history:

bash
python -m redscout.main dashboard
Then open http://localhost:8000 in your browser.

🏗️ Architecture & Workflow
Input & Scope: Validates target against the YAML Scope Guard.

Orchestration: registry.py dynamically discovers and loads requested plugins.

Execution: Plugins run concurrently using ThreadPoolExecutor.

Analysis: AI Copilot queries local Ollama API for report summarization.

Storage: Findings are encrypted into the Evidence Vault using a hash-chain.

Reporting: WeasyPrint converts the HTML template into a professional PDF.

🚧 Known Limitations & Future Roadmap
While RedScout is highly functional, I have identified several areas for architectural improvement in future versions:

Concurrency (GIL Limitation): Currently uses ThreadPoolExecutor (optimal for I/O-bound tasks).

Future: Migrate the core network layer to asyncio and httpx for massive concurrent request handling.

Pre-flight Validation (WAF Detection): Currently, active plugins send payloads directly.

Future: Implement a Pre-flight module to detect Web Application Firewalls (WAF) before running active attacks.

Context-Aware False Positives: The XSS scanner checks for payload reflection but doesn't verify executable context.

Future: Integrate AI to perform context-aware analysis of response snippets to eliminate false positives.

⚠️ Ethical Disclaimer
RedScout is designed for authorized security testing and educational purposes only.
You must have explicit, written permission to test any target. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. Unauthorized use against public infrastructure is illegal and strictly prohibited.
