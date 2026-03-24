#!/usr/bin/env bash
# vuln-scan.sh — ARIA DMZ vulnerability scan script for Kali (172.31.0.100)
# Runs nmap service/OS/vuln scan and optional nikto against the ARIA web API.

set -euo pipefail

DMZ_SUBNET="10.0.1.0/24"
ARIA_WEB="http://10.0.1.100:5000"
PORTS="80,443,5000,5432,22,3389"
DATE="$(date +%Y%m%d_%H%M%S)"
REPORT="/root/aria-vuln-report-${DATE}.txt"

log() { echo "[$(date '+%F %T')] $*" | tee -a "$REPORT"; }

echo "============================================" | tee "$REPORT"
echo " ARIA DMZ Vulnerability Scan — $(date '+%F %T')" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

# --- 1. Nmap scan ---
log "Starting nmap scan against ${DMZ_SUBNET} (ports: ${PORTS})..."
echo "" >> "$REPORT"

nmap -sV -O --script vuln -p "$PORTS" "$DMZ_SUBNET" -oN - 2>&1 | tee -a "$REPORT"

echo "" | tee -a "$REPORT"
log "Nmap scan complete."

# --- 2. Nikto web scan (if available) ---
echo "" | tee -a "$REPORT"
if command -v nikto >/dev/null 2>&1; then
    log "Running nikto against ${ARIA_WEB}..."
    echo "" >> "$REPORT"
    nikto -h "$ARIA_WEB" 2>&1 | tee -a "$REPORT"
    echo "" | tee -a "$REPORT"
    log "Nikto scan complete."
else
    log "nikto not installed — skipping web scan."
fi

# --- 3. Summary ---
echo "" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
echo " Scan Summary" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"

HOST_COUNT=$(grep -c "Nmap scan report for" "$REPORT" 2>/dev/null || echo "0")
OPEN_PORTS=$(grep -c "open" "$REPORT" 2>/dev/null || echo "0")
VULNS=$(grep -ci "VULNERABLE\|CVE-" "$REPORT" 2>/dev/null || echo "0")

echo " Hosts discovered : ${HOST_COUNT}" | tee -a "$REPORT"
echo " Open port entries : ${OPEN_PORTS}" | tee -a "$REPORT"
echo " Vulnerability hits: ${VULNS}" | tee -a "$REPORT"
echo " Full report       : ${REPORT}" | tee -a "$REPORT"
echo "============================================" | tee -a "$REPORT"
