#!/usr/bin/env bash
# ==============================================================================
# full_hunt.sh — Standalone Recon & Discovery Pipeline
# Usage: ./full_hunt.sh target.com [OPTIONS]
#
# Options:
#   --quick         Skip slow scans (amass, medium nuclei templates)
#   --recon-only    Only run passive subdomain & URL collection
#   --scan-only     Only run vulnerability scanning (nuclei, CORS)
#   --token JWT     Include Bearer token across httpx, katana, ffuf, nuclei
#   --cookie STR    Include Cookie header across tools
# ==============================================================================

set -eo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; RESET='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)] $*${RESET}"; }
ok()   { echo -e "${GREEN}[✓] $*${RESET}"; }
warn() { echo -e "${YELLOW}[!] $*${RESET}"; }
err()  { echo -e "${RED}[✗] $*${RESET}"; }
sep()  { echo -e "${BLUE}════════════════════════════════════════════════════════════${RESET}"; }

check_tool() {
    command -v "$1" &>/dev/null && echo true || echo false
}

# ── Argument Validation ───────────────────────────────────────────────────────
if [ -z "${1:-}" ]; then
    echo -e "${RED}Usage:${RESET} $0 <target-domain> [--quick] [--recon-only] [--scan-only] [--token JWT] [--cookie STR]"
    exit 1
fi

TARGET="$1"
TARGETURL="https://${TARGET}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="recon/${TARGET}_${TIMESTAMP}"

# Flags
QUICK=false
RECON_ONLY=false
SCAN_ONLY=false
TOKEN=""
COOKIE=""

shift # Remove target from positional arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --quick)       QUICK=true ;;
        --recon-only)  RECON_ONLY=true ;;
        --scan-only)   SCAN_ONLY=true ;;
        --token)       TOKEN="$2"; shift ;;
        --cookie)      COOKIE="$2"; shift ;;
        *) warn "Unknown option: $1" ;;
    esac
    shift
done

# ── Dynamic Wordlist Discovery ────────────────────────────────────────────────
locate_wordlist() {
    for path in "$@"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    echo ""
}

WL_DIRS=$(locate_wordlist \
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
    "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
    "/usr/share/wordlists/dirb/common.txt" \
    "/usr/share/dirb/wordlists/common.txt")

WL_FILES=$(locate_wordlist \
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt" \
    "/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt")

# ── Auth Header Formulation ───────────────────────────────────────────────────
AUTH_HEADERS=()
if [ -n "$TOKEN" ]; then
    AUTH_HEADERS+=(-H "Authorization: Bearer $TOKEN")
fi
if [ -n "$COOKIE" ]; then
    AUTH_HEADERS+=(-H "Cookie: $COOKIE")
fi

# ── Output Directory Setup ────────────────────────────────────────────────────
mkdir -p "$OUT"/{subdomains,urls,content,js,vulns,reports}

# ── Banner ────────────────────────────────────────────────────────────────────
sep
echo -e "${BOLD}${GREEN}  FULL HUNT RECON & VULNERABILITY PIPELINE${RESET}"
echo -e "  Target:  ${BOLD}${TARGET}${RESET}"
echo -e "  Output:  ${BOLD}${OUT}/${RESET}"
echo -e "  Started: $(date)"
[ -n "$TOKEN" ]  && echo -e "${GREEN}  Auth:    Bearer Token loaded${RESET}"
[ -n "$COOKIE" ] && echo -e "${GREEN}  Auth:    Cookie loaded${RESET}"
[ "$QUICK" = true ] && echo -e "${YELLOW}  Mode:    QUICK (extended enumerations skipped)${RESET}"
sep
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: PASSIVE RECON
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$SCAN_ONLY" = false ]; then

log "PHASE 1: Passive Reconnaissance & Discovery"
sep

# ── Subdomain Enumeration ─────────────────────────────────────────────────────
log "Enumerating subdomains..."

if [ "$(check_tool subfinder)" = true ]; then
    subfinder -d "$TARGET" -silent -o "$OUT/subdomains/subfinder.txt" 2>/dev/null || true
    ok "Subfinder: $(wc -l < "$OUT/subdomains/subfinder.txt" 2>/dev/null || echo 0) subdomains"
else
    warn "subfinder not found — skipping"
fi

if [ "$(check_tool amass)" = true ] && [ "$QUICK" = false ]; then
    log "Running Amass (passive)..."
    amass enum -passive -d "$TARGET" -o "$OUT/subdomains/amass.txt" 2>/dev/null || true
    ok "Amass: $(wc -l < "$OUT/subdomains/amass.txt" 2>/dev/null || echo 0) subdomains"
fi

# crt.sh Certificate Transparency
log "Querying crt.sh..."
curl -sk "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | \
    python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for x in data:
        for name in x.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name:
                print(name)
except Exception:
    pass
" 2>/dev/null | sort -u > "$OUT/subdomains/crtsh.txt" || true
ok "crt.sh: $(wc -l < "$OUT/subdomains/crtsh.txt" 2>/dev/null || echo 0) subdomains"

# Merge & Deduplicate
cat "$OUT"/subdomains/*.txt 2>/dev/null | sort -u > "$OUT/subdomains/all_subs.txt" || true
TOTAL_SUBS=$(wc -l < "$OUT/subdomains/all_subs.txt" 2>/dev/null || echo 0)
ok "Total Unique Subdomains: $TOTAL_SUBS"

# ── Live Host Probing ─────────────────────────────────────────────────────────
if [ "$(check_tool httpx)" = true ] && [ "$TOTAL_SUBS" -gt 0 ]; then
    log "Probing for live HTTP/HTTPS services..."
    httpx -l "$OUT/subdomains/all_subs.txt" \
        -silent \
        ${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"} \
        -o "$OUT/subdomains/live_subs.txt" 2>/dev/null || true
    ok "Live Hosts: $(wc -l < "$OUT/subdomains/live_subs.txt" 2>/dev/null || echo 0)"
fi

# ── Historical URL Discovery ──────────────────────────────────────────────────
log "Collecting historical URLs (gau / waybackurls)..."

if [ "$(check_tool gau)" = true ]; then
    gau "$TARGET" --blacklist png,jpg,gif,svg,ico,css,woff,ttf 2>/dev/null > "$OUT/urls/gau.txt" || true
    ok "GAU: $(wc -l < "$OUT/urls/gau.txt" 2>/dev/null || echo 0) URLs"
fi

if [ "$(check_tool waybackurls)" = true ]; then
    echo "$TARGET" | waybackurls 2>/dev/null > "$OUT/urls/wayback.txt" || true
    ok "Wayback: $(wc -l < "$OUT/urls/wayback.txt" 2>/dev/null || echo 0) URLs"
fi

cat "$OUT"/urls/*.txt 2>/dev/null | sort -u > "$OUT/urls/all_urls.txt" || true
ok "Total Unique Historical URLs: $(wc -l < "$OUT/urls/all_urls.txt" 2>/dev/null || echo 0)"

# ── Tech Fingerprinting ───────────────────────────────────────────────────────
if [ "$(check_tool httpx)" = true ]; then
    log "Fingerprinting target stack..."
    httpx -u "$TARGETURL" \
        -tech-detect \
        -title \
        -status-code \
        -content-length \
        -silent \
        -o "$OUT/reports/fingerprint.txt" 2>/dev/null || true
    [ -f "$OUT/reports/fingerprint.txt" ] && cat "$OUT/reports/fingerprint.txt"
fi

fi # end RECON_ONLY check

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: CONTENT & ENDPOINT DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$RECON_ONLY" = false ] && [ "$SCAN_ONLY" = false ]; then

echo ""
log "PHASE 2: Active Crawling & Endpoint Discovery"
sep

# ── Katana Web Crawler ────────────────────────────────────────────────────────
if [ "$(check_tool katana)" = true ]; then
    log "Crawling endpoints with katana..."
    katana -u "$TARGETURL" \
        -d 3 \
        -jc \
        -kf all \
        ${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"} \
        -silent \
        -o "$OUT/urls/katana.txt" 2>/dev/null || true
    
    ok "Katana: $(wc -l < "$OUT/urls/katana.txt" 2>/dev/null || echo 0) URLs discovered"
    [ -s "$OUT/urls/katana.txt" ] && cat "$OUT/urls/katana.txt" >> "$OUT/urls/all_urls.txt"
    sort -u "$OUT/urls/all_urls.txt" -o "$OUT/urls/all_urls.txt" 2>/dev/null || true
fi

# ── Directory Fuzzing ─────────────────────────────────────────────────────────
if [ "$(check_tool ffuf)" = true ] && [ -n "$WL_DIRS" ]; then
    log "Fuzzing directories with ffuf..."
    ffuf -u "$TARGETURL/FUZZ" \
        -w "$WL_DIRS" \
        -mc 200,301,302,403 \
        -t 40 \
        -s \
        ${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"} \
        -o "$OUT/content/ffuf_dirs.json" \
        -of json 2>/dev/null || true
    
    DIR_COUNT=$(python3 -c "import json; d=json.load(open('$OUT/content/ffuf_dirs.json')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
    ok "ffuf directories: $DIR_COUNT found"
else
    warn "ffuf or directory wordlist missing — skipping directory fuzzing"
fi

# ── File Extension Fuzzing ────────────────────────────────────────────────────
if [ "$(check_tool ffuf)" = true ] && [ -n "$WL_FILES" ] && [ "$QUICK" = false ]; then
    log "Fuzzing sensitive files..."
    ffuf -u "$TARGETURL/FUZZ" \
        -w "$WL_FILES" \
        -e .php,.bak,.old,.env,.json,.xml,.yml,.yaml,.txt,.zip \
        -mc 200,301,302,403 \
        -t 30 \
        -s \
        ${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"} \
        -o "$OUT/content/ffuf_files.json" \
        -of json 2>/dev/null || true
    
    FILE_COUNT=$(python3 -c "import json; d=json.load(open('$OUT/content/ffuf_files.json')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
    ok "ffuf files: $FILE_COUNT found"
fi

# ── JavaScript Extraction ─────────────────────────────────────────────────────
log "Extracting JavaScript references..."
if [ -s "$OUT/urls/all_urls.txt" ]; then
    grep -iE '\.js(\?|$)' "$OUT/urls/all_urls.txt" | sort -u > "$OUT/js/js_files.txt" || true
    ok "JS files located: $(wc -l < "$OUT/js/js_files.txt" 2>/dev/null || echo 0)"
fi

fi # end Content Discovery check

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: VULNERABILITY SCANNING
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$RECON_ONLY" = false ]; then

echo ""
log "PHASE 3: Vulnerability Scanning"
sep

# ── Nuclei Engine ─────────────────────────────────────────────────────────────
if [ "$(check_tool nuclei)" = true ]; then
    log "Running Nuclei (Critical & High)..."
    nuclei -u "$TARGETURL" \
        -severity critical,high \
        ${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"} \
        -silent \
        -o "$OUT/vulns/nuclei_critical_high.txt" 2>/dev/null || true
    
    ok "Nuclei Critical/High: $(wc -l < "$OUT/vulns/nuclei_critical_high.txt" 2>/dev/null || echo 0) findings"

    if [ "$QUICK" = false ]; then
        log "Running Nuclei (Medium)..."
        nuclei -u "$TARGETURL" \
            -severity medium \
            ${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"} \
            -silent \
            -o "$OUT/vulns/nuclei_medium.txt" 2>/dev/null || true
        ok "Nuclei Medium: $(wc -l < "$OUT/vulns/nuclei_medium.txt" 2>/dev/null || echo 0) findings"
    fi
else
    warn "nuclei not installed — skipping template scanning"
fi

# ── CORS Misconfiguration Test ────────────────────────────────────────────────
log "Testing basic CORS origin reflection..."
CORS_HEADER=$(curl -sk "$TARGETURL/" \
    ${AUTH_HEADERS[@]+"${AUTH_HEADERS[@]}"} \
    -H "Origin: https://evil.com" \
    -I 2>/dev/null | grep -i "Access-Control-Allow-Origin: https://evil.com" || true)

if [ -n "$CORS_HEADER" ]; then
    warn "Potential CORS misconfiguration detected!"
    echo "$CORS_HEADER" > "$OUT/vulns/cors_vuln.txt"
else
    ok "CORS check: No origin reflection"
fi

# ── Subdomain Takeover Probing ────────────────────────────────────────────────
if [ "$(check_tool subzy)" = true ] && [ -s "$OUT/subdomains/all_subs.txt" ]; then
    log "Running Subzy takeover check..."
    subzy run --targets "$OUT/subdomains/all_subs.txt" \
        --output "$OUT/vulns/takeover.json" \
        --hide-fails \
        --concurrency 20 2>/dev/null || true
    ok "Subzy scan complete"
fi

fi # end Vulnerability Scanning check

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY REPORT
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
sep
echo -e "${BOLD}${GREEN}  HUNT COMPLETE — EXECUTION SUMMARY${RESET}"
sep
echo -e "  Target:        ${BOLD}$TARGET${RESET}"
echo -e "  Results Path:  ${BOLD}$OUT/${RESET}"
echo -e "  Completed At:  $(date)"
echo ""

[ -f "$OUT/subdomains/all_subs.txt" ] && \
    echo -e "${YELLOW}  Subdomains Found:     $(wc -l < "$OUT/subdomains/all_subs.txt")${RESET}"
[ -f "$OUT/subdomains/live_subs.txt" ] && \
    echo -e "${YELLOW}  Live Hosts:           $(wc -l < "$OUT/subdomains/live_subs.txt")${RESET}"
[ -f "$OUT/urls/all_urls.txt" ] && \
    echo -e "${YELLOW}  Total URLs Found:     $(wc -l < "$OUT/urls/all_urls.txt")${RESET}"
[ -f "$OUT/js/js_files.txt" ] && \
    echo -e "${YELLOW}  JavaScript Files:     $(wc -l < "$OUT/js/js_files.txt")${RESET}"
[ -f "$OUT/vulns/nuclei_critical_high.txt" ] && \
    echo -e "${RED}  Nuclei Critical/High: $(wc -l < "$OUT/vulns/nuclei_critical_high.txt")${RESET}"
[ -f "$OUT/vulns/cors_vuln.txt" ] && \
    echo -e "${RED}  CORS Issues:          1${RESET}"

echo ""
echo -e "${BOLD}Recommended Next Steps:${RESET}"
echo -e "  1. Review findings: ${CYAN}cat $OUT/vulns/nuclei_critical_high.txt${RESET}"
echo -e "  2. Review JS files: ${CYAN}cat $OUT/js/js_files.txt${RESET}"
echo -e "  3. Review directories: ${CYAN}cat $OUT/content/ffuf_dirs.json${RESET}"
sep
echo ""