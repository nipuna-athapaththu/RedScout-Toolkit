# Redscout9
Mobile ethical red team orchestration framework
# 🎯 RedScout

**Mobile-First Ethical Red Team Orchestration Framework**

[![CI](https://github.com/YOUR_USERNAME/redscout/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/redscout/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

RedScout is a mobile-first red team orchestration framework with
scope enforcement, AI-assisted planning, encrypted evidence vault, and
professional PDF reporting. It runs on Android via Termux and scales to
Docker / cloud deployments.

## ✨ Features

- 🔒 **Scope Guard** - Cryptographically enforced authorization
- 🔐 **Encrypted Evidence Vault** - AES-256 + hash chain
- 🧠 **AI Copilot** - Local LLM (Ollama) for planning & reports
- 📊 **CVSS v3.1 Scorer** - Automatic severity scoring
- 🎯 **MITRE ATT&CK Mapping** - Industry standard
- 🔌 **Plugin SDK** - Extensible architecture
- 📝 **PDF/HTML Reports** - Professional deliverable
- 🖥️ **Web Dashboard** - Mobile-friendly UI
- ⏰ **Scheduler** - Recurring authorized scans
- 📢 **Notifications** - Slack / Discord / Telegram
- 🐳 **Docker Support** - Reproducible environment

## 🚀 Quick Start

### Termux (Android)

```bash
bash scripts/setup_termux.sh
python -m redscout.main -s scopes/example_scope.yaml -t 127.0.0.1