# Installation Guide

## Prerequisites

- Arch Linux (or any Linux distro)
- 8GB+ RAM
- 50GB+ free disk space
- Internet connection

## Install Tools

### 1. Pacman (Official Repos)

```bash
sudo pacman -S --noconfirm \
    nmap gobuster masscan whois bind openssl \
    sqlmap nikto tmux python
```

### 2. AUR (yay)

```bash
yay -S --noconfirm \
    subfinder amass assetfinder sublist3r \
    httpx katana gau waybackurls hakrawler \
    whatweb wafw00f cdncheck tlsx \
    nuclei ffuf dirsearch arjun trufflehog \
    asnmap mapcidr uncover metabigor cloudfox \
    jsluice kiterunner
```

### 3. Go Tools

```bash
export GOPROXY=https://goproxy.cn,direct
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

### 4. Python Tools

```bash
pipx install dnsgen
```

### 5. Wordlists

```bash
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists
nuclei -update-templates
mkdir -p ~/wordlists
curl -sL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o ~/wordlists/resolvers.txt
```

## Verify Installation

```bash
for tool in nmap subfinder amass httpx nuclei ffuf; do
    command -v $tool && echo "✅ $tool" || echo "❌ $tool"
done
```
