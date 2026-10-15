# 🔍 Recon Framework

An automated reconnaissance framework for bug bounty hunters and penetration testers.

> ⚠️ **Legal Notice:** This project is intended **ONLY** for authorized security testing on systems you have **explicit written permission** to test. Unauthorized use may result in legal consequences.

## 📋 Features

- **11 phases** of reconnaissance and vulnerability scanning
- **40+ integrated tools** (subfinder, amass, httpx, nuclei, ffuf, etc.)
- **Professional HTML report** with interactive design
- **Safe for overnight runs** — won't stop on individual tool failures

## 🚀 Installation

See [docs/INSTALL.md](docs/INSTALL.md) for detailed installation instructions.

## 🎯 Usage

```bash
# Basic run
sudo ./scripts/recon.sh example.com

# Overnight run with tmux
tmux new -s recon
sudo ./scripts/recon.sh example.com < /dev/null 2>&1 | tee -a recon.log
# Press Ctrl+B then D
# Go to sleep
