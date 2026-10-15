# Usage Guide

## Basic Usage

```bash
sudo ./scripts/recon.sh example.com
```

## Night Mode (with tmux)

```bash
tmux new -s recon
sudo ./scripts/recon.sh example.com < /dev/null 2>&1 | tee -a recon.log
# Press Ctrl+B then D
# Go to sleep
# In the morning:
tmux attach -t recon
```

## Generate HTML Report

```bash
python3 scripts/build_report.py /root/recon_example.com_TIMESTAMP
```

## Monitoring

From a second terminal:

```bash
# Watch log
sudo bash -c 'tail -f /root/recon_*/scan.log'

# Check active tools
pgrep -a "nuclei|ffuf|nmap|naabu|katana"
```
