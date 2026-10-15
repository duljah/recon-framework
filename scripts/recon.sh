#!/bin/bash
exec < /dev/null
# ==============================================================
# EXAMPLE DEEP NIGHTLY RECON — Authorized BugEx Program
# Target: *.example.com | Excluded: blog.example.com
# ==============================================================

export PATH="$PATH:/home/Duljah/go/bin:/home/Duljah/.local/bin:/usr/local/bin"
shopt -s expand_aliases
alias httpx="/home/Duljah/go/bin/httpx"
export PDCP_API_KEY="disabled"
export DISABLE_UPDATE_CHECK=true

set -o pipefail

TARGET="example.com"
EXCLUDED="blog.example.com"
WORKDIR="$HOME/recon_$(date +%Y%m%d_%H%M%S)"
LOG="$WORKDIR/scan.log"
THREADS=25
RATE_LIMIT=40
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
SECLISTS="/usr/share/wordlists/seclists"
RESOLVERS="/root/wordlists/resolvers.txt"

mkdir -p "$WORKDIR"/{01_passive,02_subs,03_live,04_fingerprint,05_dns,06_ports,07_content,08_urls,09_vulns,10_js,11_report}
cd "$WORKDIR" || exit 1
FAILED_STEPS="$WORKDIR/10_js/failed_steps.txt"
touch "$FAILED_STEPS"

log()    { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
banner() { echo ""; echo "══════════════════════════════════════════════"; echo "  $*"; echo "══════════════════════════════════════════════"; }
fail()   { echo "[FAILED] $*" | tee -a "$FAILED_STEPS"; log "❌ $*"; }
success(){ log "✅ $*"; }
free_mem() {
    sync
    sudo sysctl -w vm.drop_caches=3 >/dev/null 2>&1 || true
    local avail=$(free -m | awk '/^Mem:/ {print $7}')
    log "[MEM] Available: ${avail}MB"
    [ "$avail" -lt 400 ] && { log "⚠️ ذاكرة منخفضة — انتظار 60ث"; sleep 60; }
}

check_tools() {
    local missing=()
    for t in subfinder assetfinder sublist3r shuffledns dnsgen dnsx \
             pd-httpx katana gau waybackurls hakrawler \
             whatweb wafw00f cdncheck tlsx \
             nmap naabu ffuf dirsearch arjun kr \
             nuclei nikto jsluice trufflehog whois dig; do
        command -v "$t" &>/dev/null || missing+=("$t")
    done
    [ ${#missing[@]} -gt 0 ] && { fail "أدوات مفقودة: ${missing[*]}"; return 1; }
    success "جميع الأدوات جاهزة"
}

phase1() {
    banner "PHASE 1: Passive Reconnaissance"
    cd "$WORKDIR/01_passive" || return
    timeout 30m subfinder -d "$TARGET" -all -recursive -silent -o subfinder.txt 2>/dev/null && success "subfinder: $(wc -l < subfinder.txt)" || fail "subfinder"
    timeout 15m assetfinder --subs-only "$TARGET" > assetfinder.txt 2>/dev/null && success "assetfinder: $(wc -l < assetfinder.txt)" || fail "assetfinder"
    timeout 20m sublist3r -d "$TARGET" -o sublist3r.txt 2>/dev/null && success "sublist3r: $(wc -l < sublist3r.txt)" || fail "sublist3r"
    timeout 10m metabigor net --org "EXAMPLE" > metabigor.txt 2>/dev/null || fail "metabigor"
    timeout 2m curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > crtsh.txt && success "crt.sh: $(wc -l < crtsh.txt)" || fail "crt.sh"
    cat *.txt 2>/dev/null | grep -E "^[a-zA-Z0-9._-]+\.$TARGET$" | grep -v "^$EXCLUDED$" | sort -u > ../02_subs/all_passive.txt
    success "PHASE 1: $(wc -l < ../02_subs/all_passive.txt) نطاق"
    free_mem
}

phase2() {
    banner "PHASE 2: Active Subdomain Enumeration"
    cd "$WORKDIR/02_subs" || return
    cat all_passive.txt | dnsgen - > dnsgen.txt 2>/dev/null && success "dnsgen: $(wc -l < dnsgen.txt)" || fail "dnsgen"
    [ -f "$RESOLVERS" ] && timeout 90m shuffledns -d "$TARGET" -list dnsgen.txt -r "$RESOLVERS" -o shuffledns.txt -silent 2>/dev/null && success "shuffledns: $(wc -l < shuffledns.txt)" || fail "shuffledns"
    timeout 60m shuffledns -d "$TARGET" -w "$SECLISTS/Discovery/DNS/subdomains-top1million-20000.txt" -r "$RESOLVERS" -o shuffledns_brute.txt -silent 2>/dev/null || fail "brute"
    cat all_passive.txt shuffledns.txt shuffledns_brute.txt 2>/dev/null | grep -v "^$EXCLUDED$" | sort -u > all_subs.txt
    success "PHASE 2: $(wc -l < all_subs.txt) نطاق"
    free_mem
}

phase3() {
    banner "PHASE 3: Live Host Discovery"
    cd "$WORKDIR/03_live" || return
    timeout 60m pd-httpx -l ../02_subs/all_subs.txt -silent -status-code -title -tech-detect -cdn -tls-grab -favicon -web-server -content-length -response-time -j -threads "$THREADS" -rate-limit "$RATE_LIMIT" -o live.jsonl 2>/dev/null && success "pd-httpx: $(wc -l < live.jsonl)" || fail "pd-httpx"
    jq -r 'select(.status_code != 0) | .url' live.jsonl 2>/dev/null | sort -u > live_urls.txt
    jq -r 'select(.status_code != 0) | .host' live.jsonl 2>/dev/null | sort -u > live_hosts.txt
    timeout 20m tlsx -l live_hosts.txt -silent -san -cn -expired -o tls.txt 2>/dev/null || fail "tlsx"
    cat live_hosts.txt | cdncheck -silent -o cdn.txt 2>/dev/null || fail "cdncheck"
    success "PHASE 3: $(wc -l < live_urls.txt) مضيف حي"
    free_mem
}

phase4() {
    banner "PHASE 4: Fingerprinting & WAF"
    cd "$WORKDIR/04_fingerprint" || return
    timeout 40m whatweb -i ../03_live/live_urls.txt --log-brief=whatweb.txt --user-agent "$UA" 2>/dev/null || fail "whatweb"
    timeout 30m wafw00f -i ../03_live/live_urls.txt -f text -o waf.txt 2>/dev/null || fail "wafw00f"
    free_mem
}

phase5() {
    banner "PHASE 5: DNS & ASN"
    cd "$WORKDIR/05_dns" || return
    timeout 30m dnsx -l ../02_subs/all_subs.txt -silent -a -aaaa -cname -mx -ns -txt -resp -o dns_records.txt 2>/dev/null || fail "dnsx"
    timeout 10m dnsrecon -d "$TARGET" -t std -o dnsrecon.txt 2>/dev/null || fail "dnsrecon"
    whois "$TARGET" > asn.txt 2>/dev/null
    whois "$TARGET" > whois.txt 2>/dev/null
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' asn.txt 2>/dev/null | sort -u > cidrs.txt
    success "PHASE 5 done"
    free_mem
}

phase6() {
    banner "PHASE 6: Port Scanning"
    cd "$WORKDIR/06_ports" || return
    timeout 60m naabu -l ../03_live/live_hosts.txt -top-ports 1000 -rate 3000 -silent -o naabu.txt 2>/dev/null || fail "naabu"
    if [ -s naabu.txt ]; then
        PORTS=$(awk -F: '{print $2}' naabu.txt | sort -un | paste -sd, | head -c 2000)
        [ -n "$PORTS" ] && timeout 5h nmap -iL ../03_live/live_hosts.txt -p "$PORTS" -sV -sC -T4 --open -oA nmap_deep 2>/dev/null || fail "nmap"
    fi
    success "PHASE 6 done"
    free_mem
}

phase7() {
    banner "PHASE 7: Content Discovery"
    cd "$WORKDIR/07_content" || return
    timeout 90m katana -list ../03_live/live_urls.txt -d 3 -jc -kf all -silent -c 10 -o katana.txt 2>/dev/null || fail "katana"
    timeout 90m ffuf -u "https://$TARGET/FUZZ" -w "$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt" -mc 200,204,301,302,307,401,403 -t "$THREADS" -rate "$RATE_LIMIT" -s -o ffuf_main.json 2>/dev/null || fail "ffuf"
    timeout 60m dirsearch -u "https://$TARGET" -e php,asp,aspx,jsp,html,js,json,txt,bak,old,zip -x 404,500 -t "$THREADS" --format=json -o dirsearch.json 2>/dev/null || fail "dirsearch"
    mkdir -p arjun
    head -20 ../03_live/live_urls.txt | while read -r url; do
        hash=$(echo "$url" | md5sum | cut -c1-8)
        timeout 5m arjun -u "$url" -t 5 --stable -oT "arjun/${hash}.txt" 2>/dev/null || true
    done
    timeout 45m kr scan ../03_live/live_urls.txt -w "$SECLISTS/Discovery/Web-Content/api/api-endpoints.txt" -o json -x 10 -j 10 > kr_api.json 2>/dev/null || fail "kr"
    success "PHASE 7 done"
    free_mem
}

phase8() {
    banner "PHASE 8: Historical URLs"
    cd "$WORKDIR/08_urls" || return
    timeout 30m bash -c "cat ../02_subs/all_subs.txt | gau --threads 3 --subs > gau.txt 2>/dev/null" || fail "gau"
    timeout 30m bash -c "cat ../02_subs/all_subs.txt | waybackurls > wayback.txt 2>/dev/null" || fail "wayback"
    cat gau.txt wayback.txt 2>/dev/null | sort -u > all_urls.txt
    grep -E "(api|graphql|admin|auth|login|token|key|secret|oauth|pay|wallet|withdraw|deposit)" all_urls.txt 2>/dev/null | sort -u > interesting.txt
    success "PHASE 8: $(wc -l < all_urls.txt)"
    free_mem
}

phase9() {
    banner "PHASE 9: Vulnerability Scanning"
    cd "$WORKDIR/09_vulns" || return
    timeout 3h nuclei -l ../03_live/live_urls.txt -severity critical,high,medium -rate-limit "$RATE_LIMIT" -c 15 -stats -o nuclei_hosts.txt 2>/dev/null || fail "nuclei hosts"
    timeout 2h nuclei -l ../08_urls/interesting.txt -severity critical,high,medium -rate-limit "$RATE_LIMIT" -c 15 -o nuclei_urls.txt 2>/dev/null || fail "nuclei urls"
    timeout 1h nuclei -l ../03_live/live_urls.txt -tags exposure,misconfig,config,backup -rate-limit "$RATE_LIMIT" -c 15 -o nuclei_exposures.txt 2>/dev/null || true
    mkdir -p nikto
    head -15 ../03_live/live_urls.txt | while read -r url; do
        hash=$(echo "$url" | md5sum | cut -c1-8)
        timeout 10m nikto -h "$url" -maxtime 8m -nointeractive -o "nikto/${hash}.txt" 2>/dev/null || true
    done
    success "PHASE 9 done"
    free_mem
}

phase10() {
    banner "PHASE 10: JavaScript Analysis"
    cd "$WORKDIR/10_js" || return
    mkdir -p js_urls js_content
    cat ../08_urls/all_urls.txt ../07_content/katana.txt 2>/dev/null | grep -oE 'https?://[^"]+\.js(\?[^"]*)?' | sort -u | head -500 > js_urls/list.txt
    while read -r jsurl; do
        hash=$(echo "$jsurl" | md5sum | cut -c1-12)
        timeout 15 curl -s -A "$UA" --max-time 12 "$jsurl" -o "js_content/${hash}.js" 2>/dev/null || true
    done < js_urls/list.txt
    > jsluice_urls.txt
    > jsluice_secrets.txt
    for f in js_content/*.js; do
        [ -f "$f" ] || continue
        timeout 20 jsluice urls "$f" 2>/dev/null >> jsluice_urls.txt || true
        timeout 20 jsluice secrets "$f" 2>/dev/null >> jsluice_secrets.txt || true
    done
    sort -u jsluice_urls.txt -o jsluice_urls.txt
    timeout 30m trufflehog filesystem js_content/ --json --no-update > trufflehog.json 2>/dev/null || fail "trufflehog"
    success "PHASE 10 done"
    free_mem
}

phase11() {
    banner "PHASE 11: HTML Report"
    cd "$WORKDIR/11_report" || return
    local SD=$(date "+%Y-%m-%d %H:%M:%S")
    local SUBS=$(wc -l < ../02_subs/all_subs.txt 2>/dev/null || echo 0)
    local LIVE=$(wc -l < ../03_live/live_urls.txt 2>/dev/null || echo 0)
    local PORTS=$(wc -l < ../06_ports/naabu.txt 2>/dev/null || echo 0)
    local PATHS=$(wc -l < ../07_content/katana.txt 2>/dev/null || echo 0)
    local URLS=$(wc -l < ../08_urls/all_urls.txt 2>/dev/null || echo 0)
    local NUCLEI=$(grep -c "\[" ../09_vulns/nuclei_hosts.txt 2>/dev/null || echo 0)
    local JS_SEC=$(wc -l < ../10_js/jsluice_secrets.txt 2>/dev/null || echo 0)
    local FAILED=$(wc -l < ../10_js/failed_steps.txt 2>/dev/null || echo 0)

    cat > report.html <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>EXAMPLE Recon Report — ${SD}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0a0e1a;color:#e4e6eb;line-height:1.6;padding:20px}
.container{max-width:1400px;margin:0 auto}
header{background:linear-gradient(135deg,#1a1f35 0%,#0d1220 100%);border:1px solid #2a3050;border-radius:12px;padding:40px;margin-bottom:30px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
h1{font-size:2.5em;margin-bottom:10px;background:linear-gradient(90deg,#00ff88,#00b4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.subtitle{color:#8892a6;font-size:1.1em}
.meta{display:flex;gap:30px;margin-top:20px;flex-wrap:wrap}
.meta div{color:#b0b8c8}
.meta strong{color:#00b4ff}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}
.stat-card{background:#1a1f35;border:1px solid #2a3050;border-radius:10px;padding:25px;text-align:center;transition:all .3s}
.stat-card:hover{transform:translateY(-3px);border-color:#00b4ff;box-shadow:0 8px 24px rgba(0,180,255,.15)}
.stat-card .number{font-size:2.5em;font-weight:700;color:#00ff88}
.stat-card .label{color:#8892a6;font-size:.9em;margin-top:8px;text-transform:uppercase;letter-spacing:1px}
section{background:#1a1f35;border:1px solid #2a3050;border-radius:10px;padding:30px;margin-bottom:25px}
section h2{font-size:1.5em;margin-bottom:20px;padding-bottom:12px;border-bottom:2px solid #2a3050;color:#00b4ff}
section h2::before{content:"▸ ";color:#00ff88}
table{width:100%;border-collapse:collapse;margin-top:15px}
th,td{padding:12px 15px;text-align:left;border-bottom:1px solid #202540;font-size:.92em}
th{background:#0d1220;color:#00b4ff;font-weight:600;text-transform:uppercase;letter-spacing:.5px;font-size:.8em}
tr:hover{background:#1e2438}
td{font-family:"Courier New",monospace}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:.75em;font-weight:600;text-transform:uppercase}
.badge-critical{background:#ff3b30;color:#fff}
.badge-high{background:#ff9500;color:#fff}
.badge-medium{background:#ffcc00;color:#000}
.badge-low{background:#34c759;color:#fff}
.badge-info{background:#5ac8fa;color:#000}
.info-row{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #202540}
.info-row .k{color:#b0b8c8}
.info-row .v{color:#e4e6eb;font-family:"Courier New",monospace}
.alert{padding:15px 20px;border-radius:8px;margin:15px 0}
.alert-warning{background:rgba(255,204,0,.1);border-left:4px solid #ffcc00}
.alert-danger{background:rgba(255,59,48,.1);border-left:4px solid #ff3b30}
pre{background:#0d1220;padding:20px;border-radius:8px;overflow-x:auto;font-size:.85em;color:#b0b8c8}
footer{text-align:center;padding:30px;color:#5a6480;font-size:.9em;margin-top:40px;border-top:1px solid #2a3050}
</style>
</head>
<body>
<div class="container">
<header>
<h1>🎯 EXAMPLE Deep Recon Report</h1>
<p class="subtitle">Authorized BugEx Program — Overnight Deep Scan</p>
<div class="meta">
<div><strong>Target:</strong> *.${TARGET}</div>
<div><strong>Excluded:</strong> ${EXCLUDED}</div>
<div><strong>Scan Date:</strong> ${SD}</div>
</div>
</header>

<div class="stats-grid">
<div class="stat-card"><div class="number">${SUBS}</div><div class="label">Subdomains</div></div>
<div class="stat-card"><div class="number">${LIVE}</div><div class="label">Live Hosts</div></div>
<div class="stat-card"><div class="number">${PORTS}</div><div class="label">Open Ports</div></div>
<div class="stat-card"><div class="number">${PATHS}</div><div class="label">Paths Found</div></div>
<div class="stat-card"><div class="number">${URLS}</div><div class="label">Historical URLs</div></div>
<div class="stat-card"><div class="number">${NUCLEI}</div><div class="label">Vulnerabilities</div></div>
<div class="stat-card"><div class="number">${JS_SEC}</div><div class="label">JS Secrets</div></div>
<div class="stat-card"><div class="number">${FAILED}</div><div class="label">Failed Steps</div></div>
</div>

<section>
<h2>Executive Summary</h2>
<div class="info-row"><span class="k">Total subdomains discovered</span><span class="v">${SUBS}</span></div>
<div class="info-row"><span class="k">Live hosts responding</span><span class="v">${LIVE}</span></div>
<div class="info-row"><span class="k">Open ports detected</span><span class="v">${PORTS}</span></div>
<div class="info-row"><span class="k">Paths/endpoints crawled</span><span class="v">${PATHS}</span></div>
<div class="info-row"><span class="k">Historical URLs</span><span class="v">${URLS}</span></div>
<div class="info-row"><span class="k">Vulnerabilities (nuclei)</span><span class="v">${NUCLEI}</span></div>
<div class="info-row"><span class="k">JS secrets discovered</span><span class="v">${JS_SEC}</span></div>
<div class="info-row"><span class="k">Failed steps</span><span class="v">${FAILED}</span></div>
</section>

<section>
<h2>Live Hosts (Top 100)</h2>
<table>
<thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr></thead>
<tbody>
HTMLEOF

    [ -f ../03_live/live.jsonl ] && jq -r 'select(.status_code != 0) | "<tr><td>" + .url + "</td><td>" + (.status_code|tostring) + "</td><td>" + (.title // "-" | .[0:80]) + "</td><td>" + ((.tech // []) | join(", ")) + "</td></tr>"' ../03_live/live.jsonl 2>/dev/null | head -100 >> report.html

    cat >> report.html <<HTMLEOF
</tbody></table>
</section>

<section>
<h2>Open Ports</h2>
HTMLEOF

    if [ -s ../06_ports/nmap_deep.nmap ]; then
        echo '<pre>' >> report.html
        head -200 ../06_ports/nmap_deep.nmap | sed 's/</\&lt;/g; s/>/\&gt;/g' >> report.html
        echo '</pre>' >> report.html
    else
        echo '<div class="alert alert-warning">nmap scan did not complete. See naabu.txt.</div>' >> report.html
        [ -s ../06_ports/naabu.txt ] && { echo '<pre>' >> report.html; head -100 ../06_ports/naabu.txt >> report.html; echo '</pre>' >> report.html; }
    fi

    cat >> report.html <<HTMLEOF
</section>

<section>
<h2>Vulnerabilities (nuclei)</h2>
HTMLEOF

    if [ -s ../09_vulns/nuclei_hosts.txt ]; then
        echo '<table><thead><tr><th>Severity</th><th>Finding</th></tr></thead><tbody>' >> report.html
        grep -E "^\[" ../09_vulns/nuclei_hosts.txt | head -200 | while IFS= read -r line; do
            sev="info"
            echo "$line" | grep -qi "critical" && sev="critical"
            echo "$line" | grep -qi "high" && sev="high"
            echo "$line" | grep -qi "medium" && sev="medium"
            echo "$line" | grep -qi "low" && sev="low"
            esc=$(echo "$line" | sed 's/</\&lt;/g; s/>/\&gt;/g')
            echo "<tr><td><span class=\"badge badge-${sev}\">${sev}</span></td><td>${esc}</td></tr>" >> report.html
        done
        echo '</tbody></table>' >> report.html
    else
        echo '<div class="alert alert-warning">No nuclei findings.</div>' >> report.html
    fi

    cat >> report.html <<HTMLEOF
</section>

<section>
<h2>JavaScript Secrets</h2>
<div class="info-row"><span class="k">JS files analyzed</span><span class="v">$(ls ../10_js/js_content/ 2>/dev/null | wc -l)</span></div>
<div class="info-row"><span class="k">Endpoints extracted</span><span class="v">$(wc -l < ../10_js/jsluice_urls.txt 2>/dev/null || echo 0)</span></div>
<div class="info-row"><span class="k">Potential secrets</span><span class="v">${JS_SEC}</span></div>
HTMLEOF

    if [ -s ../10_js/jsluice_secrets.txt ]; then
        echo '<div class="alert alert-danger">⚠️ Potential secrets discovered:</div>' >> report.html
        echo '<pre>' >> report.html
        head -50 ../10_js/jsluice_secrets.txt | sed 's/</\&lt;/g; s/>/\&gt;/g' >> report.html
        echo '</pre>' >> report.html
    fi

    cat >> report.html <<HTMLEOF
</section>

<section>
<h2>Failed Steps</h2>
HTMLEOF

    if [ -s "$FAILED_STEPS" ]; then
        echo '<div class="alert alert-danger">The following steps encountered issues:</div>' >> report.html
        echo '<pre>' >> report.html
        sed 's/</\&lt;/g; s/>/\&gt;/g' "$FAILED_STEPS" >> report.html
        echo '</pre>' >> report.html
    else
        echo '<div class="alert alert-warning">No failed steps recorded.</div>' >> report.html
    fi

    cat >> report.html <<HTMLEOF
</section>

<footer>
<p><strong>EXAMPLE Deep Recon</strong> — Generated automatically</p>
<p>Authorized under BugEx Program • Responsible disclosure required</p>
<p style="margin-top:10px;">Workdir: <code>${WORKDIR}</code></p>
</footer>
</div>
</body>
</html>
HTMLEOF

    success "PHASE 11: report.html"
    echo ""
    echo "══════════════════════════════════════════════"
    echo "  🎯 التقرير جاهز: $WORKDIR/11_report/report.html"
    echo "══════════════════════════════════════════════"
}

main() {
    banner "🚀 EXAMPLE DEEP OVERNIGHT RECON STARTED"
    log "Workdir: $WORKDIR | Target: $TARGET | Threads: $THREADS"
    free_mem
    check_tools || exit 1
    phase1; phase2; phase3; phase4; phase5
    phase6; phase7; phase8; phase9; phase10; phase11
    banner "✅ SCAN COMPLETE"
    log "Report: $WORKDIR/11_report/report.html"
}

main "$@"
