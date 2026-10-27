#!/usr/bin/env bash
set -e

echo "[*] Installing system tools..."
sudo apt-get update
sudo apt-get install -y git python3 python3-pip nmap whois dnsutils hydra \
    libpango-1.0-0 libpangoft2-1.0-0

echo "[*] Installing Python deps..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo "[*] Done."