#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "[*] Updating Termux packages..."
pkg update -y && pkg upgrade -y

echo "[*] Installing core tools..."
pkg install -y git python nmap whois dnsutils hydra clang libxml2 libxslt

echo "[*] Installing Python deps..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Done. Run: python -m redscout.main --help"