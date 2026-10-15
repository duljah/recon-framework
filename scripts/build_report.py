#!/usr/bin/env python3
"""
Recon Report Builder
Reads scan results and generates an HTML report.
"""

import json
import html
import sys
from datetime import datetime
from pathlib import Path

if len(sys.argv) > 1:
    RESULTS_DIR = Path(sys.argv[1])
else:
    RESULTS_DIR = Path.home() / "recon_results"

if not RESULTS_DIR.exists():
    print(f"Directory not found: {RESULTS_DIR}")
    print("Usage: python3 build_report.py <results_dir>")
    sys.exit(1)

OUTPUT = RESULTS_DIR / "report.html"

def read_lines(filename):
    f = RESULTS_DIR / filename
    if not f.exists():
        return []
    return [l.strip() for l in f.read_text(errors='ignore').splitlines() if l.strip()]

def read_jsonl(filename):
    f = RESULTS_DIR / filename
    if not f.exists():
        return []
    items = []
    for line in f.read_text(errors='ignore').splitlines():
        if line.strip():
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items

print("[*] Reading data...")
subdomains = read_lines("subdomains.txt")
live_hosts = read_lines("live_hosts.txt")
paths = read_lines("paths.txt")
dns_records = read_lines("dns_records.txt")
detailed = read_jsonl("hosts_detailed.jsonl")

print(f"    Subdomains: {len(subdomains)}")
print(f"    Live Hosts: {len(live_hosts)}")
print(f"    Paths: {len(paths)}")
print(f"    DNS records: {len(dns_records)}")

hosts_data = []
for h in detailed:
    url = h.get("url", "")
    if not url:
        continue
    tls = h.get("tls", {}) or {}
    tech = h.get("tech", []) or []
    hosts_data.append({
        "url": url,
        "status": h.get("status_code", ""),
        "title": (h.get("title", "") or "")[:80],
        "tech": ", ".join(tech),
        "cdn": h.get("cdn_name", ""),
        "webserver": h.get("webserver", ""),
        "tls_issuer": tls.get("issuer_cn", ""),
        "host_ip": h.get("host_ip", ""),
    })

all_tech = set()
for h in hosts_data:
    for t in h["tech"].split(","):
        t = t.strip()
        if t:
            all_tech.add(t)

all_cdns = set(h["cdn"] for h in hosts_data if h["cdn"])

def esc(s):
    return html.escape(str(s))

def build_hosts_table():
    rows = []
    for h in hosts_data:
        status_color = "green" if h["status"] == 200 else "orange" if h["status"] in (301, 302) else "red" if h["status"] in (403, 401) else "gray"
        rows.append(f"""
        <tr>
            <td><a href="{esc(h['url'])}" target="_blank">{esc(h['url'])}</a></td>
            <td><span class="badge badge-{status_color}">{esc(h['status'])}</span></td>
            <td>{esc(h['title'])}</td>
            <td><small>{esc(h['tech'])}</small></td>
            <td>{esc(h['cdn']) or '-'}</td>
            <td><small>{esc(h['webserver'])}</small></td>
            <td><small>{esc(h['tls_issuer'])}</small></td>
            <td><small>{esc(h['host_ip'])}</small></td>
        </tr>""")
    return "\n".join(rows)

def build_list(items):
    if not items:
        return "<li>No data</li>"
    return "\n".join(f"<li><code>{esc(i)}</code></li>" for i in sorted(items))

def build_paths_table(limit=2000):
    rows = []
    for p in paths[:limit]:
        is_critical = any(k in p.lower() for k in ["admin", "api", "config", "backup", ".env", ".git", "login", "auth", "token", "secret"])
        cls = "critical-path" if is_critical else ""
        rows.append(f'<tr class="{cls}"><td><code>{esc(p)}</code></td></tr>')
    return "\n".join(rows)

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0e1a;color:#e4e6eb;line-height:1.6;padding:20px}}
.container{{max-width:1600px;margin:0 auto}}
header{{background:linear-gradient(135deg,#1a1f35 0%,#0d1220 100%);border:1px solid #2a3050;border-radius:12px;padding:40px;margin-bottom:30px}}
h1{{font-size:2.5em;margin-bottom:10px;background:linear-gradient(90deg,#00ff88,#00b4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:20px;margin-bottom:30px}}
.stat-card{{background:#1a1f35;border:1px solid #2a3050;border-radius:10px;padding:25px;text-align:center}}
.stat-card .number{{font-size:2.5em;font-weight:700;color:#00ff88}}
.stat-card .label{{color:#8892a6;font-size:.85em;margin-top:8px;text-transform:uppercase}}
section{{background:#1a1f35;border:1px solid #2a3050;border-radius:10px;padding:30px;margin-bottom:25px}}
section h2{{font-size:1.5em;margin-bottom:20px;padding-bottom:12px;border-bottom:2px solid #2a3050;color:#00b4ff}}
table{{width:100%;border-collapse:collapse;margin-top:15px}}
th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #202540;font-size:.88em}}
th{{background:#0d1220;color:#00b4ff;text-transform:uppercase;font-size:.78em}}
tr:hover{{background:#1e2438}}
td{{font-family:"Courier New",monospace}}
td a{{color:#5ac8fa;text-decoration:none}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:.75em;font-weight:600}}
.badge-green{{background:#34c759;color:#fff}}
.badge-orange{{background:#ff9500;color:#fff}}
.badge-red{{background:#ff3b30;color:#fff}}
.badge-gray{{background:#5a6480;color:#fff}}
.critical-path{{background:rgba(255,59,48,.08)}}
ul.tech-list{{list-style:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}}
ul.tech-list li{{padding:6px 12px;background:#0d1220;border-radius:6px;border-left:3px solid #00ff88}}
.search-box{{width:100%;padding:12px 16px;margin:10px 0 20px 0;background:#0d1220;border:1px solid #2a3050;border-radius:8px;color:#e4e6eb}}
.scrollable{{max-height:600px;overflow-y:auto;border:1px solid #202540;border-radius:8px}}
footer{{text-align:center;padding:30px;color:#5a6480;font-size:.9em;margin-top:40px;border-top:1px solid #2a3050}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🎯 Recon Report</h1>
  <p style="color:#8892a6">Automated Reconnaissance Framework</p>
  <div style="color:#b0b8c8;margin-top:15px">
    <strong style="color:#00b4ff">Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  </div>
</header>
<div class="stats-grid">
  <div class="stat-card"><div class="number">{len(subdomains)}</div><div class="label">Subdomains</div></div>
  <div class="stat-card"><div class="number">{len(live_hosts)}</div><div class="label">Live Hosts</div></div>
  <div class="stat-card"><div class="number">{len(paths)}</div><div class="label">Paths</div></div>
  <div class="stat-card"><div class="number">{len(dns_records)}</div><div class="label">DNS Records</div></div>
  <div class="stat-card"><div class="number">{len(all_tech)}</div><div class="label">Technologies</div></div>
  <div class="stat-card"><div class="number">{len(all_cdns)}</div><div class="label">CDNs</div></div>
</div>
<section>
  <h2>🖥️ Live Hosts</h2>
  <input type="text" class="search-box" id="hostSearch" placeholder="Search hosts...">
  <div class="scrollable">
    <table id="hostsTable">
      <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th><th>CDN</th><th>Server</th><th>TLS</th><th>IP</th></tr></thead>
      <tbody>{build_hosts_table()}</tbody>
    </table>
  </div>
</section>
<section>
  <h2>🛠️ Technologies ({len(all_tech)})</h2>
  <ul class="tech-list">{build_list(all_tech)}</ul>
</section>
<section>
  <h2>🌐 CDNs ({len(all_cdns)})</h2>
  <ul class="tech-list">{build_list(all_cdns)}</ul>
</section>
<section>
  <h2>📂 Paths ({len(paths)})</h2>
  <input type="text" class="search-box" id="pathSearch" placeholder="Search paths...">
  <div class="scrollable">
    <table id="pathsTable">
      <thead><tr><th>Path</th></tr></thead>
      <tbody>{build_paths_table()}</tbody>
    </table>
  </div>
</section>
<footer>
  <p><strong>Recon Framework</strong> — Automated Report</p>
  <p>Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</footer>
</div>
<script>
document.getElementById('hostSearch').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();document.querySelectorAll('#hostsTable tbody tr').forEach(tr=>{{tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none'}})}});
document.getElementById('pathSearch').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();document.querySelectorAll('#pathsTable tbody tr').forEach(tr=>{{tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none'}})}});
</script>
</body>
</html>"""

OUTPUT.write_text(html_content, encoding='utf-8')
print(f"\nReport created: {OUTPUT}")
print(f"Size: {OUTPUT.stat().st_size / 1024:.1f} KB")
