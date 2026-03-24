# ARIA Web Deployment — Claude Session Handoff (2026-03-24)

## Who is the User

Raph — cybersecurity student deploying ARIA into a Proxmox lab for a class. Technical expert, no hand-holding. Has NO Proxmox host access — can only work inside the assigned VMs. All VMs have internet (can ping 8.8.8.8).

## What is ARIA (Web Version)

ARIA is a **web-based malware analysis platform**. Users browse to the ARIA website, upload a suspicious file, and get back a full analysis report with confidence scoring, MITRE ATT&CK mapping, IOC extraction, and PDF export.

**NOT the scanner.** This is the web UI version only — `api.py` + HTML frontends. No PySide6, no filesystem scanning, no USB deployment.

## The Network (Proxmox Lab)

```
Internet
    │
Router-WAN (172.31.0.1)──── SecurityDesktop (172.31.0.100) [Kali]
    │                         └─ SOC analyst seat, pentest box
WAN Switch
    │
Firewall (192.168.2.2)
    │                    │
DMZ Switch          Firewall Switch ── Router-LAN (192.168.1.1)
    │                                       │
    │                                  Internal Switch
    │                                       │
┌───┴────────────┐          ┌───────────────┼───────────────────────┐
│ DMZ 10.0.1.x   │          │        Internal LAN 192.168.1.x      │
│                │          │                                       │
│ WebServer      │          │ ClientDesktop1    ClientDesktop2      │
│ 10.0.1.100     │          │ 192.168.1.100     192.168.1.101       │
│ [WINDOWS]      │          │ [WINDOWS]         [WINDOWS]           │
│ ← ARIA HERE    │          │ ← browse to ARIA                     │
│                │          │                                       │
│ Database       │          │ AD/DNS            Tracker             │
│ 10.0.1.200     │          │ 192.168.1.5       192.168.1.10        │
│ [RHEL]         │          │ [Win Server?]     [?]                 │
│ ← PostgreSQL   │          │                   ← Network Sentinel  │
└────────────────┘          └───────────────────────────────────────┘
```

## VM Roles

| VM | IP | OS | Role |
|---|---|---|---|
| **WebServer** | 10.0.1.100 | Windows | ARIA Flask web app + Nginx/IIS reverse proxy |
| **Database** | 10.0.1.200 | RHEL | PostgreSQL — scan results, reports, users |
| **ClientDesktop1** | 192.168.1.100 | Windows | End users — browse to ARIA, upload files |
| **ClientDesktop2** | 192.168.1.101 | Windows | End users — browse to ARIA, upload files |
| **SecurityDesktop** | 172.31.0.100 | Kali | SOC analyst — admin access to ARIA |
| **Tracker** | 192.168.1.10 | ? | Network sentinel (Suricata/Wazuh) |
| **AD/DNS** | 192.168.1.5 | Win Server? | Domain controller |

## What Needs to Be Deployed

### 1. WebServer (10.0.1.100 — Windows)

**Install:**
```powershell
# 1. Install Python 3.12+ from python.org (check "Add to PATH")
# 2. Install dependencies
pip install flask pefile python-magic-bin ppdeep requests openai yara-python reportlab gunicorn waitress jspdf

# 3. Copy project files to C:\ARIA\
#    - api.py          (Flask app — THE MAIN FILE)
#    - aria-lab.html   (main web UI)
#    - openclaw_test.html (test interface)
#    - openclaw-rules/ (YARA rules directory)
#    - tools/windows/  (capa.exe, floss.exe, upx.exe, diec.exe, aria-analyze.exe, yara64.exe)
#    - capa-rules/     (CAPA rule sets)
#    - capa-sigs/      (CAPA signatures)

# 4. Generate self-signed TLS cert
python -c "from subprocess import run; run(['openssl','req','-x509','-newkey','rsa:2048','-keyout','key.pem','-out','cert.pem','-days','365','-nodes','-subj','/CN=aria.local'])"

# 5. Run ARIA
python api.py
# Listens on https://0.0.0.0:5000
```

**CRITICAL PATH FIXES NEEDED in api.py:**
The api.py has hardcoded Linux paths that MUST be changed for Windows:
```python
# CURRENT (Linux Docker paths):
INCOMING = "/sandbox/incoming"
CAPA_RULES = "/opt/capa-rules"
CAPA_SIGS = "/opt/capa-sigs"
# HTML: send_from_directory('/sandbox', 'aria-lab.html')
# TLS: '/sandbox/cert.pem', '/sandbox/key.pem'

# NEEDS TO BE (Windows):
INCOMING = "C:\\ARIA\\incoming"
CAPA_RULES = "C:\\ARIA\\capa-rules"
CAPA_SIGS = "C:\\ARIA\\capa-sigs"
# HTML: send_from_directory('C:\\ARIA', 'aria-lab.html')
# TLS: 'C:\\ARIA\\cert.pem', 'C:\\ARIA\\key.pem'
```

The best fix: make all paths relative to api.py's directory using `os.path.dirname(os.path.abspath(__file__))` so it works on any OS without hardcoded paths.

**Tools the API calls via subprocess:**
| Tool | What it does | Binary needed |
|---|---|---|
| `capa` | Capability detection | `capa.exe` in PATH or tools/windows/ |
| `floss` | String extraction | `floss.exe` |
| `yara` | Rule matching | `yara64.exe` |
| `upx` | Unpacking | `upx.exe` |
| `diec` | Packer detection | `diec.exe` + die_win64_portable/ |
| `strings` | Basic strings | Built-in on Linux, need sysinternals `strings.exe` on Windows |
| `ghidra` | Disassembly | Optional — needs Java + Ghidra install |

**API Keys (in api.py or env vars):**
| Key | Variable | Purpose |
|---|---|---|
| OpenRouter | `OPENROUTER_API_KEY` | AI analysis (currently hardcoded at line 750 as fallback) |
| VirusTotal | `VT_API_KEY` | Hash reputation lookup |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IP reputation for IOC enrichment |

### 2. Database (10.0.1.200 — RHEL)

**Currently:** api.py uses flat JSON file cache in `/sandbox/cache/`.
**Goal:** Migrate to PostgreSQL so scan results persist, multiple users can share data, and it's realistic.

```bash
# Install PostgreSQL
sudo dnf install postgresql-server postgresql
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql

# Create database
sudo -u postgres createuser aria
sudo -u postgres createdb ariadb -O aria
sudo -u postgres psql -c "ALTER USER aria PASSWORD 'CHANGE_ME';"

# Allow connections from WebServer
# Edit /var/lib/pgsql/data/pg_hba.conf:
#   host ariadb aria 10.0.1.100/32 md5
# Edit /var/lib/pgsql/data/postgresql.conf:
#   listen_addresses = '10.0.1.200'
sudo systemctl restart postgresql
```

**Schema needed:** users, scans, findings, reports, iocs tables. api.py needs a DB adapter (psycopg2) to replace the JSON cache functions.

### 3. Tracker (192.168.1.10) — Network Sentinel

Suricata IDS monitoring all traffic through the firewall. Wazuh agents on every VM. Alerts feed into ARIA's IOC pipeline.

### 4. SecurityDesktop (172.31.0.100 — Kali)

SOC analyst seat. Accesses ARIA admin panel at `https://10.0.1.100:5000/`. Runs pentests against the deployment.

### 5. ClientDesktops (192.168.1.100/101 — Windows)

End users browse to `https://10.0.1.100:5000/` (or a DNS name like `aria.local` via AD/DNS). Upload files, view reports, download PDFs.

## Firewall Rules (Tight)

| From | To | Port | Purpose |
|---|---|---|---|
| ClientDesktops (192.168.1.x) | WebServer (10.0.1.100) | 443 | ARIA web UI |
| SecurityDesktop (172.31.0.100) | WebServer (10.0.1.100) | 443 | Admin access |
| WebServer (10.0.1.100) | Database (10.0.1.200) | 5432 | PostgreSQL |
| WebServer (10.0.1.100) | Internet | 443 | VT + OpenRouter API calls |
| Tracker (192.168.1.10) | All | monitor | IDS mirrored traffic |
| **Everything else** | ***** | ***** | **DENY** |

## api.py Architecture

The Flask app (`api.py`, ~1980 lines) provides:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Main ARIA web UI (`aria-lab.html`) |
| `/test` | GET | Test interface (`openclaw_test.html`) |
| `/upload` | POST | Upload a file for analysis |
| `/files` | GET | List uploaded files |
| `/analyze/static` | POST | Full static analysis (PE parse, CAPA, FLOSS, YARA, DIE, strings, scoring) |
| `/analyze/hash` | POST | VirusTotal hash lookup |
| `/generate_pdf` | POST | Generate PDF report |
| `/export/stix` | POST | Export findings as STIX 2.1 threat intel |
| `/enrich/iocs` | POST | IOC enrichment (AbuseIPDB, URLhaus) |
| `/generate/yara` | POST | Auto-generate YARA rules from analysis |
| `/health` | GET | Health check |

**Analysis pipeline (when user clicks "Analyze"):**
1. File info (hashes, size, magic type)
2. PE header parsing (imports, sections, entropy, timestamps, overlay, rich header, authenticode)
3. Strings extraction + categorization (network, crypto, shell, registry)
4. CAPA capability detection
5. FLOSS obfuscated string extraction
6. YARA rule matching (openclaw-rules/ + any other .yar files)
7. DIE packer/compiler detection
8. UPX unpack attempt
9. VirusTotal lookup
10. Confidence scoring (0-100 with per-indicator breakdown)
11. AI analysis via OpenRouter (Kimi K2.5 model)
12. IOC extraction (IPs, domains, URLs, file paths, registry keys)

**Confidence scoring (`compute_confidence_score()` at line 46):**
Scores 0-100 based on: VT detection rate, section entropy, import density, YARA matches, overlay analysis, rich header, authenticode, suspicious imports, CAPA capabilities, FLOSS strings, DIE detection, file size anomaly, TLS callbacks.

## Files to Copy to WebServer

```
C:\ARIA\
├── api.py                 ← Flask app (MAIN FILE — needs path fixes)
├── aria-lab.html          ← Main web UI
├── openclaw_test.html     ← Test interface
├── cert.pem               ← Generate on the box
├── key.pem                ← Generate on the box
├── incoming\              ← Upload directory (create empty)
├── cache\                 ← JSON cache directory (create empty)
├── openclaw-rules\        ← YARA rules
│   └── openclaw.yar
├── capa-rules\            ← CAPA rules
├── capa-sigs\             ← CAPA signatures
└── tools\
    └── windows\
        ├── aria-analyze.exe
        ├── capa.exe
        ├── floss.exe
        ├── upx.exe
        ├── yara64.exe
        └── die_win64_portable\
            └── diec.exe + databases/
```

## IMMEDIATE TODO for the new Claude session

1. **Fix api.py paths** — Replace all hardcoded `/sandbox/` and `/opt/` paths with relative paths that work on Windows
2. **Fix subprocess tool calls** — Tools are called as bare `capa`, `yara`, etc. On Windows they need full paths or PATH setup
3. **Replace `strings` command** — Linux `strings` doesn't exist on Windows. Either use Sysinternals strings.exe or implement in Python
4. **Add PostgreSQL adapter** — Replace JSON file cache with psycopg2 database calls
5. **Test on Windows** — Run api.py on the WebServer, verify all endpoints work
6. **Harden for pentest** — Input validation, upload sandboxing, CSP headers, rate limiting
7. **Optional: Add user auth** — Flask-Login with sessions, role-based access (analyst vs admin)
8. **Optional: Network sentinel** — Suricata + Wazuh on Tracker VM

## The Whole Thing Will Be Pentested

The deployment is subject to pentesting from SecurityDesktop (Kali). Harden:
- No path traversal in file upload (`secure_filename` already used)
- No command injection in subprocess calls (filenames passed as list args, not shell=True)
- Rate limiting on upload/analyze endpoints
- TLS only, no HTTP
- CORS restricted to internal network
- Upload size limits
- No directory listing
- CSP/X-Frame-Options/X-Content-Type-Options headers
- PostgreSQL: parameterized queries only, no string concatenation

## Scanner Version (NOT for Proxmox — separate project)

The USB scanner (PySide6 GUI, aria/ package, filesystem scanning) is a separate thing. It lives in the same repo but is NOT being deployed to Proxmox. The scanner has its own issues (Windows speed at 500 files/min — needs trusted-path skip testing). That's a different task for a different day.
