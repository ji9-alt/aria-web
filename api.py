import re
from flask import Flask, send_from_directory, request, jsonify, make_response, abort
from werkzeug.utils import secure_filename
from functools import wraps
import subprocess
import pefile
import os
import hashlib
import magic
import ppdeep
import requests
import json
import time
import secrets
from openai import OpenAI

app = Flask(__name__)
app.secret_key = os.environ.get("ARIA_SECRET_KEY", secrets.token_hex(32))

# ══════════════════════════════════════
#  SECURITY MIDDLEWARE
# ══════════════════════════════════════

@app.after_request
def security_headers(response):
    """Add security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://www.paypal.com https://www.sandbox.paypal.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://www.paypalobjects.com https://t.paypal.com; "
        "frame-src https://www.sandbox.paypal.com https://www.paypal.com; "
        "connect-src 'self' https://www.sandbox.paypal.com https://www.paypal.com"
    )
    return response

def require_auth(f):
    """Decorator: require valid session token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('aria_session')
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        try:
            import db
            session = db.get_session(token)
        except Exception:
            session = None
        if not session:
            return jsonify({"error": "Invalid or expired session"}), 401
        request.user = session
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('aria_session')
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        try:
            import db
            session = db.get_session(token)
        except Exception:
            session = None
        if not session or session.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        request.user = session
        return f(*args, **kwargs)
    return decorated

def rate_limit(max_req=30, window=60):
    """Decorator: rate limit by IP."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                import db
                if not db.check_rate_limit(request.remote_addr, f.__name__, max_req, window):
                    return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
            except Exception:
                pass
            return f(*args, **kwargs)
        return decorated
    return decorator


# ══════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════

@app.route("/api/login", methods=["POST"])
@rate_limit(max_req=10, window=60)
def api_login():
    """Authenticate user, return session cookie."""
    data = request.get_json(force=True)
    username = str(data.get("username", "")).strip()[:64]
    password = str(data.get("password", ""))[:128]

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    try:
        import db
        user = db.authenticate(username, password)
    except Exception as e:
        # DB not available — fall back to hardcoded for demo
        user = None
        if username == "admin" and password == "AriaAdmin2026!":
            user = {"id": 0, "username": "admin", "role": "admin"}
        elif username == "analyst" and password == "AriaAnalyst2026!":
            user = {"id": 0, "username": "analyst", "role": "analyst"}

    if not user:
        time.sleep(1)  # Slow down brute force
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        import db
        token = db.create_session(user['id'], user['username'], user['role'])
    except Exception:
        token = secrets.token_urlsafe(32)

    resp = make_response(jsonify({"ok": True, "username": user['username'], "role": user['role']}))
    resp.set_cookie('aria_session', token, httponly=True, samesite='Strict', max_age=28800)
    return resp

@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Destroy session."""
    token = request.cookies.get('aria_session')
    if token:
        try:
            import db
            db.destroy_session(token)
        except Exception:
            pass
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie('aria_session')
    return resp

@app.route("/api/me")
def api_me():
    """Get current user info."""
    token = request.cookies.get('aria_session')
    if not token:
        return jsonify({"authenticated": False}), 401
    try:
        import db
        session = db.get_session(token)
        if session:
            # Get extended profile
            profile = db.get_user_profile(session['user_id']) or {}
            return jsonify({
                "authenticated": True,
                "username": session['username'],
                "role": session['role'],
                "full_name": profile.get('full_name', session['username']),
                "email": profile.get('email', ''),
                "organization": profile.get('organization', ''),
            })
    except Exception:
        pass
    return jsonify({"authenticated": False}), 401

@app.route("/api/history")
@require_auth
def api_history():
    """Get scan history for current user."""
    try:
        import db
        if request.user.get('role') == 'admin':
            scans = db.get_all_scans(100)
        else:
            scans = db.get_user_scans(request.user['user_id'], 50)
        # Convert datetime objects to strings
        for s in scans:
            if 'submitted_at' in s and s['submitted_at']:
                s['submitted_at'] = s['submitted_at'].isoformat()
        return jsonify({"scans": scans})
    except Exception as e:
        return jsonify({"scans": [], "error": str(e)})

@app.route("/api/stats")
def api_stats():
    """Get dashboard stats."""
    try:
        import db
        return jsonify({
            "total_scans": db.get_scan_count(),
            "threats": db.get_threat_count(),
            "iocs": db.get_ioc_count(),
        })
    except Exception:
        return jsonify({"total_scans": 0, "threats": 0, "iocs": 0})


@app.route("/api/analytics")
@require_auth
def api_analytics():
    """Full analytics data for the dashboard."""
    try:
        import db
        # Basic counts
        total_scans = db.get_scan_count()
        threats = db.get_threat_count()
        iocs = db.get_ioc_count()

        # User counts
        users = db.query_one("SELECT COUNT(*) as cnt FROM users") or {'cnt': 0}

        # Order stats
        orders = db.query_one("SELECT COUNT(*) as cnt, COALESCE(SUM(total),0) as revenue FROM orders") or {'cnt': 0, 'revenue': 0}

        # Threat breakdown
        breakdown = db.query("""
            SELECT verdict, COUNT(*) as cnt FROM scans
            GROUP BY verdict ORDER BY cnt DESC
        """) or []

        # Recent scans
        recent = db.query("""
            SELECT s.sha256, s.filename, s.verdict, s.score, s.label, s.submitted_at,
                   u.username as analyst
            FROM scans s LEFT JOIN users u ON s.submitted_by = u.id
            ORDER BY s.submitted_at DESC LIMIT 20
        """) or []
        for r in recent:
            if r.get('submitted_at'):
                r['submitted_at'] = r['submitted_at'].isoformat()

        # Scans per day (last 7 days)
        daily = db.query("""
            SELECT DATE(submitted_at) as day, COUNT(*) as cnt
            FROM scans WHERE submitted_at > NOW() - INTERVAL '7 days'
            GROUP BY DATE(submitted_at) ORDER BY day
        """) or []
        for d in daily:
            if d.get('day'):
                d['day'] = d['day'].isoformat()

        # Top YARA matches from findings
        yara_top = db.query("""
            SELECT indicator, COUNT(*) as cnt FROM findings
            WHERE category LIKE '%YARA%' OR category LIKE '%yara%'
            GROUP BY indicator ORDER BY cnt DESC LIMIT 10
        """) or []

        # Active services
        services = db.query("""
            SELECT product_id, name, COUNT(*) as cnt FROM user_services
            WHERE status = 'active' GROUP BY product_id, name ORDER BY cnt DESC
        """) or []

        return jsonify({
            "total_scans": total_scans,
            "threats": threats,
            "iocs": iocs,
            "total_users": users['cnt'],
            "total_orders": orders['cnt'],
            "revenue": float(orders['revenue']),
            "threat_breakdown": [dict(r) for r in breakdown],
            "recent_scans": [dict(r) for r in recent],
            "daily_scans": [dict(r) for r in daily],
            "yara_top": [dict(r) for r in yara_top],
            "active_services": [dict(r) for r in services],
        })
    except Exception as e:
        print(f"[ANALYTICS] Error: {e}")
        return jsonify({"error": str(e), "total_scans": 0, "threats": 0, "iocs": 0, "total_users": 0,
                        "total_orders": 0, "revenue": 0, "threat_breakdown": [], "recent_scans": [],
                        "daily_scans": [], "yara_top": [], "active_services": []})

@app.route("/analytics")
def serve_analytics():
    return send_from_directory(BASE_DIR, "analytics.html")


# ══════════════════════════════════════
#  USER REGISTRATION
# ══════════════════════════════════════

@app.route("/api/register", methods=["POST"])
@rate_limit(max_req=5, window=60)
def api_register():
    """Register a new user account."""
    data = request.get_json(force=True)
    full_name = str(data.get("full_name", "")).strip()[:128]
    email = str(data.get("email", "")).strip()[:128]
    organization = str(data.get("organization", "")).strip()[:128]
    username = str(data.get("username", "")).strip()[:32]
    password = str(data.get("password", ""))[:128]
    password2 = str(data.get("password2", ""))[:128]

    if not full_name or not email or not username or not password:
        return jsonify({"error": "All fields are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if password != password2:
        return jsonify({"error": "Passwords do not match"}), 400
    if not re.match(r'^[a-zA-Z0-9_]{3,32}$', username):
        return jsonify({"error": "Username: 3-32 chars, letters/numbers/underscores"}), 400
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        return jsonify({"error": "Invalid email address"}), 400

    try:
        import db
        user = db.register_user(username, password, full_name, email, organization)
        if not user:
            return jsonify({"error": "Username or email already exists"}), 409
        return jsonify({"ok": True, "username": user['username']}), 201
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500


# ══════════════════════════════════════
#  CUSTOMER PORTAL APIs
# ══════════════════════════════════════

@app.route("/api/my/apikey")
@require_auth
def api_my_apikey():
    """Get current user's API key."""
    try:
        import db
        key = db.get_or_create_apikey(request.user['user_id'])
        return jsonify({"api_key": key})
    except Exception as e:
        return jsonify({"api_key": None, "error": str(e)})

@app.route("/api/my/apikey/regenerate", methods=["POST"])
@require_auth
def api_regen_apikey():
    """Regenerate current user's API key."""
    try:
        import db
        key = db.regenerate_apikey(request.user['user_id'])
        return jsonify({"api_key": key})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/my/orders")
@require_auth
def api_my_orders():
    """Get current user's order history."""
    try:
        import db
        uid = request.user['user_id']
        print(f"[PORTAL] Loading orders for user_id={uid}")
        orders = db.get_user_orders(uid)
        print(f"[PORTAL] Found {len(orders)} orders")
        for o in orders:
            if 'created_at' in o and o['created_at']:
                o['created_at'] = o['created_at'].isoformat()
        return jsonify({"orders": orders})
    except Exception as e:
        print(f"[PORTAL] Orders error: {e}")
        return jsonify({"orders": [], "error": str(e)})

@app.route("/api/my/services")
@require_auth
def api_my_services():
    """Get current user's active services."""
    try:
        import db
        uid = request.user['user_id']
        print(f"[PORTAL] Loading services for user_id={uid}")
        services = db.get_user_services(uid)
        print(f"[PORTAL] Found {len(services)} services")
        for s in services:
            if 'activated_at' in s and s['activated_at']:
                s['activated_at'] = s['activated_at'].isoformat()
        return jsonify({"services": services})
    except Exception as e:
        print(f"[PORTAL] Services error: {e}")
        return jsonify({"services": [], "error": str(e)})

@app.route("/api/my/downloads")
@require_auth
def api_my_downloads():
    """Get current user's available downloads."""
    try:
        import db
        uid = request.user['user_id']
        print(f"[PORTAL] Loading downloads for user_id={uid}")
        downloads = db.get_user_downloads(uid)
        print(f"[PORTAL] Found {len(downloads)} downloads")
        return jsonify({"downloads": downloads})
    except Exception as e:
        print(f"[PORTAL] Downloads error: {e}")
        return jsonify({"downloads": [], "error": str(e)})


# All paths relative to where api.py lives (works on Windows + Linux)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INCOMING = os.path.join(BASE_DIR, "incoming")
CAPA_RULES = os.path.join(BASE_DIR, "capa-rules")
CAPA_SIGS = os.path.join(BASE_DIR, "capa-sigs")
VT_API_KEY = os.environ.get("VT_API_KEY", "")

os.makedirs(INCOMING, exist_ok=True)

ANALYSIS_CACHE = {}
CACHE_DIR = os.path.join(BASE_DIR, "cache")
os.makedirs(CACHE_DIR, exist_ok=True)

def load_cache(key):
    path = os.path.join(CACHE_DIR, key + ".json")
    if os.path.exists(path):
        try:
            return json.load(open(path))
        except:
            return None
    return None

def save_cache(key, data):
    path = os.path.join(CACHE_DIR, key + ".json")
    try:
        json.dump(data, open(path, "w"))
    except:
        pass



def compute_confidence_score(results):
    """
    Score each indicator 0-10. Sum and normalize to 0-100.
    Returns dict with total, label, and per-indicator breakdown.
    """
    score = 0
    max_score = 0
    breakdown = []

    def add(label, points, earned, reason):
        nonlocal score, max_score
        max_score += points
        score += earned
        breakdown.append({"label": label, "points": points, "earned": earned, "reason": reason})

    pe = results.get("pe_info", {}) or {}
    vt = results.get("virustotal", {}) or {}
    yara = results.get("yara", {}) or {}
    floss = results.get("floss", {}) or {}
    overlay = pe.get("overlay", {}) or {}
    rich = pe.get("rich_header", {}) or {}
    auth = pe.get("authenticode", {}) or {}
    tls = pe.get("tls_callbacks", {}) or {}
    sections = pe.get("sections", []) or []
    imports = pe.get("imports", []) or []
    sus_imports = pe.get("suspicious_imports", []) or []
    filesize = results.get("size", 0) or 0
    strings = results.get("strings", {}) or {}
    capa = results.get("capa", {}) or {}

    # VT detection rate
    mal = vt.get("malicious", 0) or 0
    tot = (vt.get("malicious",0) or 0) + (vt.get("suspicious",0) or 0) + (vt.get("undetected",0) or 0)
    det_pct = (mal / tot * 100) if tot > 0 else 0
    if det_pct > 50:   add("VT Detection", 10, 10, f"{det_pct:.1f}% detection -- strong consensus")
    elif det_pct > 25: add("VT Detection", 10,  8, f"{det_pct:.1f}% detection -- significant")
    elif det_pct > 10: add("VT Detection", 10,  5, f"{det_pct:.1f}% detection -- moderate")
    elif det_pct > 0:  add("VT Detection", 10,  3, f"{det_pct:.1f}% detection -- low but non-zero")
    else:              add("VT Detection", 10,  6, "0/0 -- unknown sample, not confirmed clean")

    # High entropy sections — threshold 6.0 (packed binaries rarely exceed 6.5)
    high_ent = [s for s in sections if s.get("entropy", 0) > 6.0]
    zeroed   = [s for s in sections if s.get("entropy", 0) == 0.0]
    if len(high_ent) >= 2 and len(zeroed) >= 1:
        add("Section Entropy", 15, 15, f"{len(high_ent)} high-entropy + {len(zeroed)} zeroed sections -- textbook packer")
    elif len(high_ent) >= 1:
        add("Section Entropy", 15, 8, f"{len(high_ent)} high-entropy section(s)")
    else:
        add("Section Entropy", 15, 0, "No high-entropy sections")

    # Import density — high import count from suspicious DLLs is the signal
    total_imports = sum(len(e.get("functions", [])) for e in imports)
    if total_imports > 200:
        add("Import Density", 10, 10, f"{total_imports} imports -- dense malware profile")
    elif total_imports > 50:
        add("Import Density", 10, 5, f"{total_imports} imports -- moderate")
    elif filesize > 5_000_000 and total_imports < 5:
        add("Import Density", 10, 8, f"Only {total_imports} imports in large binary -- minimized/packed")
    else:
        add("Import Density", 10, 0, f"{total_imports} imports -- normal")

    # YARA matches -- pipeline stores as results["yara_matches"] list
    _yara_raw = results.get("yara_matches", [])
    yara_count = len(_yara_raw) if isinstance(_yara_raw, list) else (_yara_raw.get("match_count", 0) if isinstance(_yara_raw, dict) else 0)
    if yara_count >= 3:   add("YARA Signatures", 10, 10, f"{yara_count} rule matches")
    elif yara_count >= 1: add("YARA Signatures", 10,  6, f"{yara_count} rule match(es)")
    else:                 add("YARA Signatures", 10,  0, "No YARA matches")

    # Overlay — bonus indicator only; absence is normal and not penalised
    _ov_size = (overlay.get("size") or 0)
    if overlay.get("present") and (_ov_size > 500000 or overlay.get("suspicious")):
        add("Overlay", 8, 8, f"Overlay at {overlay.get('offset','?')} ({_ov_size} bytes) -- likely encrypted payload")
    elif overlay.get("present"):
        add("Overlay", 8, 3, "Small overlay present")
    # else: no overlay is normal — don't add to max_score

    # Missing Rich header (evasion indicator) — only counts when actually suspicious
    if not rich.get("present") and filesize > 1_000_000:
        add("Rich Header", 7, 7, "Absent in large binary -- likely stripped for evasion")
    elif not rich.get("present"):
        add("Rich Header", 7, 2, "Absent in small binary -- less significant")
    # else: present = normal compiler artifact — no points either way

    # Unsigned binary
    if not auth.get("present"):
        add("Authenticode", 5, 5, "Unsigned binary")
    else:
        add("Authenticode", 5, 0, "Signed binary")

    # Suspicious imports -- compute from raw imports since pe_info lacks this field
    _susp_kws = {"GetAsyncKeyState","GetClipboardData","BlockInput","SetWindowsHookExA",
        "SetWindowsHookExW","IsDebuggerPresent","OpenProcess","WinExec",
        "CreateToolhelp32Snapshot","VirtualAllocEx","WriteProcessMemory",
        "CreateRemoteThread","CryptEncrypt","RegSetValueExA","RegSetValueExW",
        "WinHttpConnect","WinHttpSendRequest","BitBlt"}
    _found_susp = []
    for _dll in imports:
        for _fn in _dll.get("functions", []):
            if _fn in _susp_kws: _found_susp.append(_fn)
    # also check pe_info.suspicious_imports if present
    _found_susp += list(sus_imports)
    _found_susp = list(set(_found_susp))
    if len(_found_susp) >= 3:  add("Suspicious Imports", 8, 8, f"{len(_found_susp)} suspicious API imports")
    elif len(_found_susp) >= 1: add("Suspicious Imports", 8, 4, f"{len(_found_susp)} suspicious API import(s)")
    else:                       add("Suspicious Imports", 8, 0, "No suspicious imports detected")

    # CAPA matches
    capa_matches = len(capa.get("capabilities", []) or [])
    die_data = results.get("die", {}) or {}
    die_raw = die_data.get("raw", "") or ""
    _packer_blind = (capa_matches == 0) and (die_raw != "" or any(
        s.get("entropy", 0) > 6.0 for s in (results.get("pe_info", {}) or {}).get("sections", [])))
    if capa_matches >= 5:   add("CAPA Capabilities", 10, 10, f"{capa_matches} capability matches")
    elif capa_matches >= 2: add("CAPA Capabilities", 10,  6, f"{capa_matches} capability matches")
    elif capa_matches >= 1: add("CAPA Capabilities", 10,  3, "1 capability match")
    elif _packer_blind:     add("CAPA Capabilities", 10,  8, "0 matches -- packer detected, CAPA blind (evasion indicator)")
    else:                   add("CAPA Capabilities", 10,  2, "0 matches -- no packer, genuinely sparse")

    # Ghidra suspicious function names
    ghidra = results.get("ghidra", {}) or {}
    gh_suspicious = ghidra.get("suspicious_functions", []) or []
    if len(gh_suspicious) >= 10:
        add("Ghidra Symbols", 10, 10, f"{len(gh_suspicious)} suspicious function names (CRT symbols excluded)")
    elif len(gh_suspicious) >= 3:
        add("Ghidra Symbols", 10,  7, f"{len(gh_suspicious)} suspicious function names (CRT symbols excluded)")
    elif len(gh_suspicious) >= 1:
        add("Ghidra Symbols", 10,  4, f"{len(gh_suspicious)} suspicious function name(s)")
    else:
        add("Ghidra Symbols", 10,  0, "No suspicious symbols detected (CRT symbols excluded)")

    # TLS callbacks — bonus indicator; absence is normal and not penalised
    if tls.get("present"):
        add("TLS Callbacks", 7, 7, f"{tls.get('count',0)} pre-entry callbacks -- anti-analysis indicator")
    # else: no TLS is the baseline — don't add to max_score

    # FLOSS string categories
    _floss = results.get("floss", {}) or {}
    _fl_filt = _floss.get("filtered", {}) or {}
    _fl_net    = len(_fl_filt.get("network_or_path", []) or [])
    _fl_crypto = len(_fl_filt.get("crypto",          []) or [])
    _fl_shell  = len(_fl_filt.get("shell",           []) or [])
    _fl_total  = _fl_net + _fl_crypto + _fl_shell
    if _fl_total >= 15:
        add("FLOSS Strings", 8, 8, f"{_fl_net} network + {_fl_crypto} crypto + {_fl_shell} shell strings")
    elif _fl_total >= 8:
        add("FLOSS Strings", 8, 6, f"{_fl_total} suspicious strings across categories")
    elif _fl_total >= 3:
        add("FLOSS Strings", 8, 4, f"{_fl_total} suspicious strings")
    else:
        add("FLOSS Strings", 8, 0, "No suspicious strings in FLOSS output")

    # ARIA LLM verdict
    _aria      = results.get("aria", {}) or {}
    _aria_text = _aria.get("executive_report", "") or ""
    _aria_m    = re.search(r'VERDICT[:\s*]*(MALICIOUS|SUSPICIOUS|BENIGN)', _aria_text, re.IGNORECASE)
    _aria_v    = _aria_m.group(1).upper() if _aria_m else None
    if _aria_v == "MALICIOUS":
        add("ARIA Verdict", 8, 8, "LLM analysis confirms MALICIOUS")
    elif _aria_v == "SUSPICIOUS":
        add("ARIA Verdict", 8, 5, "LLM analysis flagged SUSPICIOUS")
    elif _aria_v == "BENIGN":
        add("ARIA Verdict", 8, 0, "LLM verdict: BENIGN")
    else:
        add("ARIA Verdict", 8, 3, "ARIA verdict unavailable")

    # DIE packer detection
    _die_results = (results.get("die", {}) or {}).get("results", []) or []
    _die_raw = (results.get("die", {}) or {}).get("raw", "") or ""
    _pe_sections = [s.get("name","") for s in (results.get("pe_info",{}) or {}).get("sections",[]) or []]
    _nonstandard_secs = sum(1 for s in _pe_sections if s.startswith("/"))
    _die_packer = any(r.get("raw","") not in ("PE64","PE32","") for r in _die_results) or (_die_raw not in ("PE64","PE32","")) or _nonstandard_secs >= 3
    if _die_packer:
        add("DIE Packer", 5, 5, f"{_nonstandard_secs} non-standard sections -- custom crypter confirmed")
    elif _die_raw in ("PE64", "PE32"):
        add("DIE Packer", 5, 2, "No packer ID -- custom or unknown crypter")
    else:
        add("DIE Packer", 5, 0, "DIE produced no output")

    pct = round((score / max_score * 100)) if max_score > 0 else 0
    if pct >= 75:   label = "HIGH"
    elif pct >= 45: label = "MEDIUM"
    else:           label = "LOW"

    return {
        "score": score,
        "max_score": max_score,
        "percent": pct,
        "label": label,
        "breakdown": breakdown
    }

def compute_hashes(filepath):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        data = f.read()
    md5.update(data)
    sha1.update(data)
    sha256.update(data)
    fuzzy = ppdeep.hash(data)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "ssdeep": fuzzy,
        "size_bytes": len(data)
    }


def get_file_type(filepath):
    try:
        mime = magic.from_file(filepath, mime=True)
        desc = magic.from_file(filepath)
        return {"mime": mime, "description": desc}
    except Exception as e:
        return {"error": str(e)}


def get_strings(filepath, min_len=6):
    try:
        out = subprocess.check_output(
            ["strings", "-n", str(min_len), filepath],
            timeout=30
        )
        lines = out.decode(errors="ignore").splitlines()
        # Filter interesting strings
        interesting = []
        keywords = [
            "http", "https", "ftp", "\\\\", "HKEY_", "cmd", "powershell",
            "CreateRemoteThread", "VirtualAlloc", "WriteProcessMemory",
            "WScript", "eval", "base64", "decrypt", "encrypt", "socket",
            "connect", "download", "execute", "inject", "payload", "shell"
        ]
        for line in lines:
            for kw in keywords:
                if kw.lower() in line.lower():
                    interesting.append(line)
                    break
        return {
            "total_count": len(lines),
            "all_strings": lines[:500],  # cap at 500
            "interesting_strings": list(set(interesting))
        }
    except Exception as e:
        return {"error": str(e)}


def analyze_pe(filepath):
    try:
        pe = pefile.PE(filepath)
        result = {
            "is_pe": True,
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
            "compile_timestamp_human": time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.gmtime(pe.FILE_HEADER.TimeDateStamp)
            ),
            "entrypoint": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": [],
            "imports": [],
            "exports": [],
            "suspicious_imports": []
        }

        # Suspicious import indicators
        suspicious = [
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
            "CreateRemoteThread", "NtUnmapViewOfSection", "SetWindowsHookEx",
            "GetAsyncKeyState", "URLDownloadToFile", "ShellExecute",
            "WinExec", "CreateProcess", "OpenProcess", "ReadProcessMemory",
            "CryptEncrypt", "CryptDecrypt", "RegSetValueEx", "RegCreateKey",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "GetTickCount", "Sleep", "NtQueryInformationProcess"
        ]

        # Sections
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            entropy = section.get_entropy()
            result["sections"].append({
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "size": section.SizeOfRawData,
                "entropy": round(entropy, 4),
                "high_entropy": entropy > 7.0
            })

        # Imports
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode(errors="ignore")
                        funcs.append(fname)
                        if fname in suspicious:
                            result["suspicious_imports"].append({
                                "dll": dll,
                                "function": fname
                            })
                result["imports"].append({"dll": dll, "functions": funcs})

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result["exports"].append(exp.name.decode(errors="ignore"))

        # Imphash
        try:
            result["imphash"] = pe.get_imphash()
        except Exception:
            result["imphash"] = "n/a"


        # Rich header
        try:
            rich = pe.parse_rich_header()
            if rich:
                entries = []
                values = rich.get("values", [])
                for i in range(0, len(values) - 1, 2):
                    comp_id = values[i]
                    count   = values[i + 1]
                    entries.append({"prod_id": (comp_id >> 16) & 0xFFFF, "build": comp_id & 0xFFFF, "count": count})
                result["rich_header"] = {"present": True, "checksum": hex(rich.get("checksum", 0)), "entries": entries, "entry_count": len(entries)}
            else:
                result["rich_header"] = {"present": False}
        except Exception as _e:
            result["rich_header"] = {"present": False, "error": str(_e)}

        # Overlay
        try:
            overlay_off = pe.get_overlay_data_start_offset()
            if overlay_off is not None:
                overlay_size = len(pe.__data__) - overlay_off
                overlay_bytes = pe.__data__[overlay_off:overlay_off + min(overlay_size, 65536)]
                freq = [0] * 256
                for b in overlay_bytes: freq[b] += 1
                n = len(overlay_bytes)
                import math as _math
                entropy = -sum((f/n) * _math.log2(f/n) for f in freq if f > 0)
                result["overlay"] = {"present": True, "offset": hex(overlay_off), "size": overlay_size, "entropy": round(entropy, 4), "suspicious": entropy > 7.0}
            else:
                result["overlay"] = {"present": False}
        except Exception as _e:
            result["overlay"] = {"present": False, "error": str(_e)}

        # Authenticode
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY:
                result["authenticode"] = {"present": True, "note": "Signature present - verify with osslsigncode for full chain"}
            else:
                result["authenticode"] = {"present": False}
        except Exception as _e:
            result["authenticode"] = {"present": False, "error": str(_e)}

        # TLS callbacks
        try:
            tls_callbacks = []
            if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
                tls = pe.DIRECTORY_ENTRY_TLS.struct
                callback_rva = tls.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
                ptr_size = 8 if pe.PE_TYPE == 0x20b else 4
                for _ in range(32):
                    cb_ptr = pe.get_qword_at_rva(callback_rva) if ptr_size == 8 else pe.get_dword_at_rva(callback_rva)
                    if cb_ptr == 0: break
                    tls_callbacks.append(hex(cb_ptr))
                    callback_rva += ptr_size
            result["tls_callbacks"] = {"present": len(tls_callbacks) > 0, "callbacks": tls_callbacks, "count": len(tls_callbacks)}
        except Exception as _e:
            result["tls_callbacks"] = {"present": False, "error": str(_e)}

        return result

    except pefile.PEFormatError:
        return {"is_pe": False, "error": "Not a valid PE file"}
    except Exception as e:
        return {"is_pe": False, "error": str(e)}



def run_ghidra(filepath):
    import subprocess, json, tempfile, os, hashlib, time
    JAVA_HOME = '/usr/lib/jvm/java-21-openjdk-amd64'
    GHIDRA    = os.path.join(BASE_DIR, 'tools', 'ghidra', 'support', 'analyzeHeadless')
    SCRIPT    = os.path.join(BASE_DIR, 'ghidra_scripts')
    if not os.path.exists(GHIDRA):
        return {"error": "Ghidra not installed", "available": False}
    # Cache by file hash
    fhash = hashlib.md5(filepath.encode()).hexdigest()
    cache_path = f'/tmp/ghidra_cache_{fhash}.json'
    if os.path.exists(cache_path):
        try:
            return json.load(open(cache_path))
        except:
            pass
    proj_dir = f'/tmp/ghidra_proj_{fhash}'
    out_json = f'/tmp/ghidra_out_{fhash}.json'
    os.makedirs(proj_dir, exist_ok=True)
    try:
        env = os.environ.copy()
        env['JAVA_HOME'] = JAVA_HOME
        r = subprocess.run(
            [GHIDRA, proj_dir, 'aria_proj',
             '-import', filepath,
             '-scriptPath', SCRIPT,
             '-postScript', 'ghidra_extract.py', out_json,
             '-deleteProject',
             '-analysisTimeoutPerFile', '180'],
            env=env, capture_output=True, timeout=300
        )
        if os.path.exists(out_json):
            data = json.load(open(out_json))
            # Summarize for ARIA
            named_fns = [f for f in data.get('functions', [])
                        if not f['name'].startswith('FUN_')
                        and not f['name'].startswith('thunk_')
                        and len(f['name']) > 3]
            # Known MSVC/GCC CRT internal symbol prefixes — always false positives
            _CRT_FALSE_POSITIVE_PREFIXES = (
                '__scrt_', '__acrt_', '___acrt_', '__crt', '___crt',
                '__Init_thread', '__register_thread_local_exe_atexit',
                '__execute_onexit', '__configthreadlocale',
                'replace_current_thread_locale_nolock',
                'ExFilterRethrow', '_Execute_once', '___crtInitOnceExecuteOnce',
                '__register_frame', '__std_', '__isa_', '_RTC_', '__RTD',
                '__CxxFrameHandler', '__GSHandlerCheck', '__security_',
            )
            _CRT_FALSE_POSITIVE_EXACT = {
                'operator(),class_&,class__>', '__execute_onexit_table',
                '_Execute_once', 'ExFilterRethrow',
            }
            # Keywords that only flag if they appear as standalone semantic units,
            # not buried in CRT boilerplate like "thread_safe_statics"
            _SUSPICIOUS_KEYWORDS = [
                'inject','hook','keylog','shell',
                'download','upload','steal','capture','hidden',
                'persist','registry','bypass','evad','decrypt',
                'encrypt','ransom','spread','lateral','pivot',
                'exfil','c2','beacon','payload','dropper',
                'hollow','remote','debug','anti',
                # crypt/exec only if not a CRT function
            ]
            suspicious_fns = []
            for f in named_fns:
                fname = f['name']
                fname_lower = fname.lower()
                # Skip known CRT false positives
                if any(fname.startswith(p) for p in _CRT_FALSE_POSITIVE_PREFIXES):
                    continue
                if fname in _CRT_FALSE_POSITIVE_EXACT:
                    continue
                # Check for genuine malicious keywords
                if any(k in fname_lower for k in _SUSPICIOUS_KEYWORDS):
                    suspicious_fns.append(fname)
                    continue
                # crypt/exec: only flag if not a generic CRT wrapper
                if 'crypt' in fname_lower and not fname_lower.startswith('__'):
                    suspicious_fns.append(fname)
                elif 'exec' in fname_lower and 'execute_once' not in fname_lower and not fname_lower.startswith('__') and not fname_lower.startswith('_execute'):
                    suspicious_fns.append(fname)
            result = {
                'available': True,
                'total_functions': len(data.get('functions', [])),
                'named_functions': len(named_fns),
                'total_imports': len(data.get('imports', [])),
                'suspicious_functions': suspicious_fns[:30],
                'named_function_sample': [f['name'] for f in named_fns[:50]],
                'imports_sample': [i['name'] for i in data.get('imports', [])[:50]]
            }
            json.dump(result, open(cache_path, 'w'))
            return result
        else:
            return {'available': True, 'error': 'Script ran but no output produced',
                    'stderr': r.stderr.decode(errors='ignore')[-500:]}
    except subprocess.TimeoutExpired:
        return {'available': True, 'error': 'Ghidra analysis timed out (300s)'}
    except Exception as e:
        return {'available': True, 'error': str(e)}
    finally:
        try:
            import shutil
            shutil.rmtree(proj_dir, ignore_errors=True)
            if os.path.exists(out_json): os.unlink(out_json)
        except:
            pass

def run_die(filepath):
    try:
        import subprocess as _sp, re, re
        out = _sp.check_output(
            ["diec", filepath],
            stderr=_sp.DEVNULL,
            timeout=30
        ).decode("utf-8", errors="replace")
        out = re.sub(r"\x1b\[[0-9;]*m", "", out).strip()
        results = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            entry = {"raw": line}
            if len(parts) == 2:
                entry["type"] = parts[0]
                kv = parts[1].split(":", 1)
                if len(kv) == 2:
                    entry["category"] = kv[0].strip()
                    entry["value"] = kv[1].strip()
                else:
                    entry["value"] = parts[1].strip()
            results.append(entry)
        return {"results": results, "raw": out, "error": None}
    except Exception as e:
        return {"results": [], "raw": "", "error": str(e)}


def run_floss(filepath):
    import subprocess as _sp, re as _re, json as _json
    VERSION_KW = ["CompanyName","FileDescription","ProductName","OriginalFilename",
                  "InternalName","FileVersion","ProductVersion","LegalCopyright"]
    PKI_KW     = ["digicert","ocsp","cacerts","verisign","comodo","sectigo",
                  "certificate","authenticode","pkcs","x509","crl","thawte"]
    SHELL_KW   = ["powershell","cmd.exe","wscript","cscript","mshta","rundll32",
                  "regsvr32","certutil","bitsadmin","schtasks","wmic"]
    CRYPTO_KW  = ["encrypt","decrypt","base64","aes","rsa","rc4","xor",
                  "cipher","payload","shellcode","inject","loader"]
    NET_RE  = _re.compile(
        r"https?://|ftp://|\.onion|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"[A-Za-z0-9-]{3,}\.(com|net|org|io|gov|edu|ru|cn|xyz)", _re.IGNORECASE)
    PATH_RE = _re.compile(
        r"[A-Za-z]:\\|/etc/|/tmp/|/var/|AppData|System32|ProgramData|"
        r"Temp\\|\.exe|\.dll|\.sys|\.bat|\.ps1|\.vbs", _re.IGNORECASE)
    REG_RE  = _re.compile(
        r"HKEY_|HKLM\\|HKCU\\|SOFTWARE\\|CurrentVersion|Run\b", _re.IGNORECASE)

    def categorize(s):
        sl = s.lower()
        for kw in VERSION_KW:
            if kw.lower() in sl: return "version"
        for kw in PKI_KW:
            if kw in sl: return "pki"
        for kw in SHELL_KW:
            if kw in sl: return "shell"
        for kw in CRYPTO_KW:
            if kw in sl: return "crypto"
        if NET_RE.search(s) or PATH_RE.search(s) or REG_RE.search(s):
            return "network_or_path"
        words = [w for w in _re.split(r"[\s_\-./\\]+", s)
                 if len(w) >= 3 and _re.search(r"[a-zA-Z]", w)]
        if len(words) >= 2: return "multiword"
        return None

    try:
        raw_out = _sp.check_output(
            ["floss", "--only", "static", "-j", filepath],
            stderr=_sp.DEVNULL, timeout=90
        ).decode("utf-8", errors="replace")
        data = _json.loads(raw_out)
        static_strings = data.get("strings", {}).get("static_strings", [])
        buckets = {k: [] for k in
                   ["version","pki","shell","crypto","network_or_path","multiword"]}
        seen = set()
        for entry in static_strings:
            s = (entry.get("string","") if isinstance(entry, dict) else str(entry)).strip()
            if len(s) < 8 or not _re.search(r"[a-zA-Z]", s) or s in seen:
                continue
            cat = categorize(s)
            if cat and len(buckets[cat]) < 40:
                buckets[cat].append(s)
                seen.add(s)
        return {
            "error": None,
            "total_static_strings": len(static_strings),
            "total_filtered": sum(len(v) for v in buckets.values()),
            "filtered": buckets,
        }
    except _sp.TimeoutExpired:
        return {"error": "floss timed out",
                "total_static_strings": 0, "total_filtered": 0, "filtered": {}}
    except Exception as exc:
        return {"error": str(exc),
                "total_static_strings": 0, "total_filtered": 0, "filtered": {}}

def run_capa(filepath):
    try:
        out = subprocess.check_output(
            [
                "capa",
                "--rules", CAPA_RULES,
                "--signatures", CAPA_SIGS,
                "--json",
                filepath
            ],
            timeout=120,
            stderr=subprocess.DEVNULL
        )
        data = json.loads(out.decode())
        # Extract key findings
        capabilities = []
        mitre = []
        mbc = []

        if "rules" in data:
            for rule_name, rule_data in data["rules"].items():
                capabilities.append(rule_name)
                # MITRE ATT&CK
                if "attack" in rule_data.get("meta", {}):
                    for attack in rule_data["meta"]["attack"]:
                        mitre.append({
                            "tactic": attack.get("tactic", ""),
                            "technique": attack.get("technique", ""),
                            "id": attack.get("id", "")
                        })
                # MBC
                if "mbc" in rule_data.get("meta", {}):
                    for m in rule_data["meta"]["mbc"]:
                        mbc.append({
                            "objective": m.get("objective", ""),
                            "behavior": m.get("behavior", ""),
                            "id": m.get("id", "")
                        })

        return {
            "capabilities": capabilities,
            "mitre_attack": mitre,
            "mbc": mbc,
            "total_rules_matched": len(capabilities)
        }

    except subprocess.TimeoutExpired:
        return {"error": "CAPA timed out (>120s)"}
    except json.JSONDecodeError:
        return {"error": "CAPA output was not valid JSON"}
    except Exception as e:
        return {"error": str(e)}


def run_yara(filepath):
    import glob as _glob
    YARA_RULE_DIRS = [
        os.path.join(BASE_DIR, "openclaw-rules"),
        os.path.join(BASE_DIR, "yara_rules"),
    ]
    all_matches = []
    errors = []
    for rules_dir in YARA_RULE_DIRS:
        if not os.path.isdir(rules_dir):
            continue
        rule_files = _glob.glob(rules_dir + "/*.yar") + _glob.glob(rules_dir + "/*.yara")
        for rule_file in rule_files:
            try:
                out = subprocess.check_output(
                    ["yara", rule_file, filepath],
                    timeout=60,
                    stderr=subprocess.DEVNULL
                )
                lines = out.decode(errors="ignore").strip().splitlines()
                for line in lines:
                    if line and line not in all_matches:
                        all_matches.append(line)
            except subprocess.CalledProcessError:
                pass
            except Exception as e:
                errors.append(f"{rule_file}: {str(e)}")
    result = {"matches": all_matches, "match_count": len(all_matches)}
    if errors:
        result["errors"] = errors
    return result


def check_virustotal(file_hash):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured"}
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        elif resp.status_code == 404:
            return {"found": False, "message": "Hash not found in VirusTotal"}
        else:
            return {"error": f"VT API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}



OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "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")
ARIA_MODEL = os.environ.get("ARIA_MODEL", "moonshotai/kimi-k2.5")

def aria_analyze(report_data):
    if not OPENROUTER_API_KEY:
        return {"error": "OPENROUTER_API_KEY not configured"}
    try:
        client = OpenAI(api_key=OPENROUTER_API_KEY, base_url="https://openrouter.ai/api/v1", timeout=180.0)
        h = report_data.get("hashes", {})
        analyst_notes_raw = report_data.get("analyst_notes", "") or ""
        analyst_notes_block = analyst_notes_raw.strip() if analyst_notes_raw.strip() else "NO ANALYST NOTES PROVIDED -- ARIA operating without context"
        pe = report_data.get("pe_info", {})
        pe_info = pe
        ghidra_info = report_data.get("ghidra", {}) or {}
        vt = report_data.get("virustotal", {})
        capa = report_data.get("capa", {})
        strings = report_data.get("strings", {})
        floss_data     = report_data.get("floss", {}) or {}
        floss_filtered = floss_data.get("filtered", {})
        floss_total    = floss_data.get("total_static_strings", 0)
        floss_kept     = floss_data.get("total_filtered", 0)
        floss_error    = floss_data.get("error", None)
        yara = report_data.get("yara_matches", [])
        sections = pe.get("sections", [])
        suspicious_imports = pe.get("suspicious_imports", [])
        interesting_strings = strings.get("interesting", [])
        all_strings = strings.get("all_strings", [])
        capabilities = capa.get("capabilities", [])
        mitre = capa.get("mitre_attack", [])
        mbc = capa.get("mbc", [])
        all_imports = pe.get("imports", [])
        exports = pe.get("exports", [])
        high_entropy = [s for s in sections if float(s.get("entropy", 0)) > 7.0]
        med_entropy = [s for s in sections if 6.0 < float(s.get("entropy", 0)) <= 7.0]
        is_packed = len(high_entropy) > 0 and len(capabilities) == 0
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        undet = vt.get("undetected", 0)
        harm = vt.get("harmless", 0)
        tot = mal + sus + undet + harm
        det_pct = (mal/tot*100) if tot > 0 else 0
        vt_verdict = "MALICIOUS" if det_pct > 15 else "SUSPICIOUS" if mal > 0 else "CLEAN"
        filesize = report_data.get("size", 0)
        compile_time = pe.get("compile_time", "N/A")
        imphash = pe.get("imphash", "N/A")
        ssdeep_hash = h.get("ssdeep", "N/A")

        # Known packer section name signatures
        known_packers = {
            "UPX0": "UPX packer", "UPX1": "UPX packer", "UPX2": "UPX packer",
            ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
            ".themida": "Themida/WinLicense", ".winlicense": "WinLicense",
            ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
            ".aspack": "ASPack", ".adata": "ASPack",
            "!": "Enigma Protector", ".enigma1": "Enigma Protector",
            ".packed": "Generic packer", ".shrink1": "PEShrinker",
            ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
            "execryptor": "ExeCryptor", ".pec1": "PECompact", ".pec2": "PECompact"
        }
        detected_packers = []

        # DIE (Detect-It-Easy) results
        die_data = report_data.get("die", {})
        die_results = die_data.get("results", []) if die_data else []
        die_raw = die_data.get("raw", "") if die_data else ""
        die_summary = []
        for dr in die_results:
            # Support both JSON format (name/version/info) and text-parsed format (type/category/value)
            raw = dr.get("raw", "").strip()
            if not raw:
                continue
            # Skip bare type lines like "PE64" with no useful info
            typ = dr.get("type", "").strip().rstrip(":")
            val = dr.get("value", "").strip()
            name = dr.get("name", "").strip()
            ver = dr.get("version", "").strip()
            info = dr.get("info", "").strip()
            cat = dr.get("category", "").strip()

            if name:
                entry = f"{typ}: {name}"
                if ver: entry += f" {ver}"
                if info: entry += f" [{info}]"
            elif val:
                entry = f"{typ} {cat}: {val}" if (typ and cat) else (f"{typ}: {val}" if typ else val)
            elif raw and " " in raw:
                entry = raw
            else:
                continue  # skip bare lines like "PE64"
            if entry and entry.strip():
                die_summary.append(entry.strip())
        # Always include raw output as fallback
        if not die_summary and die_raw:
            die_summary = [line.strip() for line in die_raw.splitlines() if line.strip()]
        die_display = chr(10).join(f"  {d}" for d in die_summary) if die_summary else "  No detections or DIE not available"
        section_names = [s.get("name","").strip() for s in sections]
        for sname in section_names:
            for sig, pname in known_packers.items():
                if sig.lower() in sname.lower():
                    detected_packers.append(pname)

        # Known RAT/malware import fingerprints
        import_fingerprints = {
            "GetAsyncKeyState": "keylogger capability",
            "SetWindowsHookEx": "keyboard/mouse hook — keylogger or injection",
            "VirtualAllocEx": "remote process memory allocation — injection",
            "WriteProcessMemory": "process hollowing/injection",
            "CreateRemoteThread": "remote thread injection — classic shellcode injection",
            "NtUnmapViewOfSection": "process hollowing",
            "URLDownloadToFile": "file download from C2",
            "WinExec": "command execution",
            "ShellExecute": "shell command execution",
            "CryptEncrypt": "encryption capability — ransomware/data stealing",
            "CryptDecrypt": "decryption — config/payload decryption",
            "RegSetValueEx": "registry persistence",
            "RegCreateKey": "registry key creation — persistence",
            "IsDebuggerPresent": "anti-debugging",
            "CheckRemoteDebuggerPresent": "anti-debugging",
            "NtQueryInformationProcess": "anti-debugging / process inspection",
            "GetTickCount": "timing-based anti-sandbox",
            "Sleep": "anti-sandbox sleep evasion",
            "OpenProcess": "process access — injection or enumeration",
            "ReadProcessMemory": "process memory reading — credential theft",
        }
        import_analysis = {}
        for imp in suspicious_imports:
            for func, meaning in import_fingerprints.items():
                if func.lower() in str(imp).lower():
                    import_analysis[func] = meaning

        full_prompt = f"""You are ARIA — Automated Reverse Engineering and Intelligence Agent.
You are the world's foremost malware analyst, combining the expertise of:
- CrowdStrike Falcon Intelligence (nation-state APT tracking, TTP attribution)
- Mandiant FLARE Team (advanced RE, packer analysis, exploit development)
- NSA TAO (offensive implant analysis, zero-day identification)
- CISA (critical infrastructure threat assessment)
- VirusTotal Intelligence (large-scale malware taxonomy, family clustering)
- Kaspersky GReAT (APT campaigns, threat actor attribution)
- ESET Research (rootkit and bootkit analysis)

You have personally analyzed over 2 million malware samples. You recognize:

MALWARE FAMILIES (you know all of these intimately):
RATs: AsyncRAT, NjRAT, DarkComet, QuasarRAT, Remcos, XWorm, DCRat, BitRAT, Warzone, NanoCore, Gh0st, Orcus
Stealers: RedLine, Vidar, Raccoon, AZORult, AgentTesla, FormBook, LokiBot, Arkei, Mars, Titan, Lumma
Loaders: Emotet, IcedID, BazarLoader, GootLoader, Bumblebee, Raspberry Robin, PrivateLoader, SmokeLoader
Ransomware: LockBit, BlackCat/ALPHV, Conti, REvil/Sodinokibi, Ryuk, BlackMatter, Hive, Vice Society, Play, BlackBasta, Cl0p, MedusaLocker
Botnets: Mirai, QakBot/Qbot, TrickBot, Dridex, Zeus, Gozi, Ursnif
Backdoors: Cobalt Strike Beacon, Meterpreter, Sliver, Brute Ratel, PoisonIvy, PlugX, ShadowPad
APT Implants: Turla Snake, APT29 WellMess, APT28 X-Agent, Lazarus Group BLINDINGCAN, OilRig POWERSTATS, Equation Group implants
Packers/Crypters: UPX, MPRESS, Themida, VMProtect, Obsidium, Enigma, ASPack, PECompact, NsPack, ConfuserEx, .NET Reactor, Babel, SmartAssembly, Dotfuscator

PACKER SECTION SIGNATURES DETECTED: {detected_packers if detected_packers else "None matched known signatures"}

DETECT-IT-EASY (DIE) ANALYSIS:
{die_display}
[DIE provides compiler, linker, packer, and tool detection — treat as HIGH CONFIDENCE ground truth]
[If DIE identifies a packer, use that name. If DIE shows compiler/linker, factor into legitimacy assessment]
[Custom section names + DIE showing no packer = custom/unknown crypter, NOT clean binary]

IMPORT FINGERPRINT ANALYSIS:
{chr(10).join([f"  {func}: {meaning}" for func, meaning in import_analysis.items()]) if import_analysis else "  No fingerprints matched"}

You are now performing a COMPLETE PROGRESSIVE ANALYSIS. You will reason through every evidence layer systematically, exactly as you would during a real incident response engagement.

═══════════════════════════════════════════════════════════
TOOL OUTPUT — LAYER 0: DETECT-IT-EASY (DIE) CLASSIFICATION
═══════════════════════════════════════════════════════════
{die_display}
Raw DIE Output: {die_raw}

═══════════════════════════════════════════════════════════
=========================================================
TOOL OUTPUT - LAYER FLOSS: FLOSS STATIC STRINGS
=========================================================
Total static strings : {floss_total}
Analyst strings kept : {floss_kept}
{('floss ERROR: ' + str(floss_error)) if floss_error else 'floss OK -- static mode only (emulation skipped: packed binary)'}

VERSION RESOURCE STRINGS (masquerade detection):
{chr(10).join(['  ' + s for s in floss_filtered.get('version', [])]) if floss_filtered.get('version') else '  None found'}
[Compare to signing cert owner -- mismatch = identity masquerade]

PKI / CERTIFICATE STRINGS:
{chr(10).join(['  ' + s for s in floss_filtered.get('pki', [])]) if floss_filtered.get('pki') else '  None found'}
[Embedded cert URLs in packed binary = likely stolen/abused code-signing cert]

SHELL / EXECUTION STRINGS:
{chr(10).join(['  ' + s for s in floss_filtered.get('shell', [])]) if floss_filtered.get('shell') else '  None found'}

CRYPTO / OBFUSCATION STRINGS:
{chr(10).join(['  ' + s for s in floss_filtered.get('crypto', [])]) if floss_filtered.get('crypto') else '  None found'}

NETWORK / PATH / REGISTRY STRINGS:
{chr(10).join(['  ' + s for s in floss_filtered.get('network_or_path', [])]) if floss_filtered.get('network_or_path') else '  None found -- likely encrypted in packed payload'}

OTHER MULTI-WORD STRINGS (top 20):
{chr(10).join(['  ' + s for s in floss_filtered.get('multiword', [])[:20]]) if floss_filtered.get('multiword') else '  None found'}

=========================================================
TOOL OUTPUT - LAYER 0c: PE ENRICHMENT
=========================================================
RICH HEADER: {('PRESENT -- ' + str(pe_info.get("rich_header",{}).get("entry_count",0)) + ' toolchain entries, checksum ' + str(pe_info.get("rich_header",{}).get("checksum","?"))) if pe_info.get("rich_header",{}).get("present") else 'NOT PRESENT -- binary may be hand-crafted, stripped, or header was zeroed (evasion indicator)'}
[Rich header reveals true compiler/linker. Absence in a large binary is suspicious. Mismatch with timestamp = forged metadata.]

OVERLAY: {('PRESENT -- offset=' + str(pe_info.get("overlay",{}).get("offset","?")) + ' size=' + str(pe_info.get("overlay",{}).get("size","?")) + ' bytes entropy=' + str(pe_info.get("overlay",{}).get("entropy","?")) + (' -- SUSPICIOUS HIGH ENTROPY: likely encrypted appended payload or config blob' if pe_info.get("overlay",{}).get("suspicious") else ' -- low entropy')) if pe_info.get("overlay",{}).get("present") else 'NOT PRESENT'}
[Overlay = data appended after PE end. High entropy overlay = strong indicator of appended encrypted payload or dropper stage.]

AUTHENTICODE: {('SIGNED -- ' + str(pe_info.get("authenticode",{}).get("note",""))) if pe_info.get("authenticode",{}).get("present") else 'NOT SIGNED -- unsigned binary'}
[Unsigned binary with embedded DigiCert cert URLs = stolen cert abuse. The cert strings are NOT a signature, they are embedded data.]

TLS CALLBACKS: {('PRESENT -- ' + str(pe_info.get("tls_callbacks",{}).get("count",0)) + ' callbacks at: ' + str(pe_info.get("tls_callbacks",{}).get("callbacks",[]))) if pe_info.get("tls_callbacks",{}).get("present") else 'NONE -- no pre-entry execution detected'}
[TLS callbacks execute BEFORE entry point. Used for anti-debug/anti-VM. Absence does not rule out runtime anti-analysis.]
=========================================================
TOOL OUTPUT - LAYER 0d: GHIDRA STATIC ANALYSIS
=========================================================
{('GHIDRA UNAVAILABLE: ' + str(ghidra_info.get('error','unknown'))) if not ghidra_info.get('available') or ghidra_info.get('error') else ''}
TOTAL FUNCTIONS  : {ghidra_info.get('total_functions','N/A')}
NAMED FUNCTIONS  : {ghidra_info.get('named_functions','N/A')}
TOTAL IMPORTS    : {ghidra_info.get('total_imports','N/A')}
SUSPICIOUS FUNCTIONS: {', '.join(ghidra_info.get('suspicious_functions',[])) or 'NONE DETECTED'}
IMPORTS SAMPLE   : {', '.join(ghidra_info.get('imports_sample',[])[:20]) or 'N/A'}
[Suspicious function names are strong behavioral indicators even without dynamic analysis.]
=========================================================

=========================================================
ANALYST CONTEXT NOTES (provided by submitting analyst)
=========================================================
{analyst_notes_block}

TOOL OUTPUT — LAYER 1: SAMPLE IDENTIFICATION
═══════════════════════════════════════════════════════════
Filename : {report_data.get("filename","unknown")}
MD5      : {h.get("md5","N/A")}
SHA1     : {h.get("sha1","N/A")}
SHA256   : {h.get("sha256","N/A")}
ssdeep   : {ssdeep_hash}
Size     : {filesize} bytes ({filesize/1048576:.2f} MB)
Type     : {report_data.get("file_type",{}).get("description","N/A")}

IMPHASH INTELLIGENCE: {imphash}
[If this imphash matches any known malware family builder, identify it immediately]

SSDEEP CLUSTERING NOTE: {ssdeep_hash[:20]}...
[If this ssdeep prefix matches known malware clusters, identify them]

═══════════════════════════════════════════════════════════
TOOL OUTPUT — LAYER 2: VIRUSTOTAL INTELLIGENCE
═══════════════════════════════════════════════════════════
Detection Ratio : {vt.get("detection_ratio","N/A")} ({det_pct:.1f}% detection rate)
Malicious       : {mal}
Suspicious      : {sus}
Undetected      : {undet}
Harmless        : {harm}
AUTOMATED VERDICT: {vt_verdict}

VT ANALYSIS NOTES:
- Detection rate {det_pct:.1f}%: {"HIGH — strong consensus this is malicious" if det_pct > 50 else "MODERATE — significant detection, likely malicious" if det_pct > 15 else "LOW — could be new/evasive malware or false positive" if mal > 0 else "ZERO — no signatures match, may be new/unknown"}
- {"Low detection on packed binary is EXPECTED — AV engines cannot scan inside the encrypted payload. Do not interpret as clean." if is_packed else ""}
- {"Recent compile date with low detection suggests this may be a new variant or custom build." if "2024" in compile_time or "2025" in compile_time or "2026" in compile_time else ""}

═══════════════════════════════════════════════════════════
TOOL OUTPUT — LAYER 3: PE STRUCTURE ANALYSIS
═══════════════════════════════════════════════════════════
Machine      : {pe.get("machine","N/A")} {"(64-bit)" if "8664" in str(pe.get("machine","")) else "(32-bit)" if "014c" in str(pe.get("machine","")).lower() else ""}
Compile Time : {compile_time}
Entry Point  : {pe.get("entrypoint","N/A")}
Image Base   : {pe.get("image_base","N/A")}
Imphash      : {imphash}

SECTION TABLE (full entropy analysis):
{"Name":12} {"Entropy":8} {"VirtSize":10} {"RawSize":10} {"Assessment"}
{"-"*65}
{chr(10).join([f"  {s.get('name','?'):12} {float(s.get('entropy',0)):.4f}   {s.get('virtual_size',0):10} {s.get('raw_size',0):10}  {'ENCRYPTED/PACKED - entropy >7.8' if float(s.get('entropy',0)) > 7.8 else 'LIKELY PACKED - entropy 7.0-7.8' if float(s.get('entropy',0)) > 7.0 else 'COMPRESSED - entropy 6.0-7.0' if float(s.get('entropy',0)) > 6.0 else 'NORMAL - entropy <6.0' if float(s.get('entropy',0)) > 0.5 else 'ZEROED/EMPTY - entropy ~0'}" for s in sections])}

ENTROPY INTERPRETATION:
- 0.0-1.0: Zeroed/empty sections (often stub sections in packed files)
- 1.0-6.0: Normal code/data
- 6.0-7.0: Compressed data
- 7.0-7.8: Likely encrypted/packed
- 7.8-8.0: Almost certainly encrypted (max theoretical entropy = 8.0)

HIGH ENTROPY SECTIONS: {[s.get("name") for s in high_entropy]}
MEDIUM ENTROPY SECTIONS: {[s.get("name") for s in med_entropy]}
ZEROED SECTIONS: {[s.get("name") for s in sections if float(s.get("entropy",0)) < 0.5]}
PACKING ASSESSMENT: {"PACKED/OBFUSCATED — high entropy sections with zeroed stubs is the classic packing pattern" if is_packed else "NOT OBVIOUSLY PACKED — sections show normal entropy distribution"}

KNOWN PACKER SIGNATURES IN SECTION NAMES: {detected_packers if detected_packers else "None — custom or unknown packer if packed"}

SUSPICIOUS IMPORTS (pre-filtered):
{chr(10).join([f"  {i}" for i in suspicious_imports]) if suspicious_imports else "  None in filtered list"}

FULL IMPORT TABLE:
{chr(10).join([f"  [{imp.get('dll','?')}] -> {[f if isinstance(f, str) else f.get('name','?') for f in imp.get('functions',[])[:12]]}" for imp in all_imports[:20]]) if all_imports else "  Not parseable — consistent with packing (no real IAT visible)"}

EXPORTS: {exports[:20] if exports else "None"}

IMPORT FINGERPRINT MATCHES:
{chr(10).join([f"  {func} -> {meaning}" for func, meaning in import_analysis.items()]) if import_analysis else "  None matched — either minimal imports (packed) or clean"}

═══════════════════════════════════════════════════════════
TOOL OUTPUT — LAYER 4: STRING EXTRACTION
═══════════════════════════════════════════════════════════
Total strings extracted: {strings.get("total_count",0)}
Expected for {filesize/1048576:.1f}MB file: ~{int(filesize/1048576)*500}+ strings if unpacked
String density: {"VERY LOW — strong packing/encryption indicator" if strings.get("total_count",0) < 100 and filesize > 1000000 else "LOW — possible packing" if strings.get("total_count",0) < 500 and filesize > 500000 else "NORMAL"}

KEYWORD-FILTERED INTERESTING STRINGS:
{chr(10).join([f"  [{i+1:02d}] {s}" for i,s in enumerate(interesting_strings[:50])]) if interesting_strings else "  NONE — file contents appear encrypted (consistent with packing)"}

ADDITIONAL STRINGS (raw sample):
{chr(10).join([f"  {s}" for s in all_strings[:30] if s not in interesting_strings and len(s) > 4]) if all_strings else "  None recoverable"}

STRING INTELLIGENCE NOTES:
- C2 indicators: {"YES — network strings found" if any("http" in s.lower() or "://" in s.lower() for s in interesting_strings) else "None visible — may be encrypted in packed payload"}
- Registry artifacts: {"YES" if any("hkey" in s.lower() or "software\\" in s.lower() for s in interesting_strings) else "None visible"}
- Certificate strings: {"YES — embedded cert infrastructure URLs found" if any("digicert" in s.lower() or "ocsp" in s.lower() or "cacerts" in s.lower() for s in interesting_strings) else "None"}
- Crypto indicators: {"YES" if any("encrypt" in s.lower() or "decrypt" in s.lower() or "aes" in s.lower() or "rsa" in s.lower() for s in interesting_strings) else "None visible"}

═══════════════════════════════════════════════════════════
TOOL OUTPUT — LAYER 5: CAPA CAPABILITY DETECTION
═══════════════════════════════════════════════════════════
Total rules matched: {len(capabilities)}
Analysis result: {"ZERO MATCHES — CAPA cannot analyze packed binaries. The real code is encrypted. This is expected behavior for packed malware and does NOT indicate the binary is clean." if len(capabilities) == 0 and is_packed else "ZERO MATCHES — unexpected for unpacked binary, may indicate unsupported format" if len(capabilities) == 0 else f"{len(capabilities)} capabilities identified"}

{chr(10).join([f"  [{i+1:02d}] {c}" for i,c in enumerate(capabilities[:50])]) if capabilities else ""}

MITRE ATT&CK (from CAPA):
{chr(10).join([f"  {m.get('id','?'):14} [{m.get('tactic','?'):20}] {m.get('technique','?')}" for m in mitre[:25]]) if mitre else "  None from CAPA — INFER FROM IMPORTS AND STRINGS BELOW"}

MBC BEHAVIORS:
{chr(10).join([f"  [{m.get('objective','?')}] {m.get('behavior','?')} ({m.get('id','?')})" for m in mbc[:20]]) if mbc else "  None from CAPA"}

═══════════════════════════════════════════════════════════
TOOL OUTPUT — LAYER 6: YARA SIGNATURES
═══════════════════════════════════════════════════════════
{chr(10).join([f"  MATCH: {y}" for y in yara]) if yara else "  No YARA matches — ruleset may not cover this family or binary is packed"}

═══════════════════════════════════════════════════════════
PRE-ANALYSIS INTELLIGENCE CHECKS
═══════════════════════════════════════════════════════════

TIMESTAMP ANALYSIS:
- Compile time: {compile_time}
- Plausibility check: {"Future date — FORGED TIMESTAMP" if "2026" in compile_time or "2027" in compile_time else "Very old date (pre-2010) — likely forged" if any(y in compile_time for y in ["1970","1971","1980","1990","2000","2001","2002","2003","2004","2005"]) else "Plausible date range"}
- Note: Malware frequently forges timestamps to evade time-based detection rules

FALSE POSITIVE ASSESSMENT FRAMEWORK:
Consider false positive ONLY if ALL of these are true:
1. VT detection < 5% AND detections are only heuristic engines
2. No suspicious imports at all
3. Normal section entropy throughout
4. Recognizable legitimate software strings
5. Valid digital signature from known vendor
6. File size consistent with claimed software type
Current sample meets criteria: {"UNCLEAR — requires full analysis" if mal < 5 else "NO — VT detections too high for false positive"}

PACKING/OBFUSCATION EVIDENCE SUMMARY:
{"STRONG EVIDENCE OF PACKING: " + ", ".join([
    "High entropy sections: " + str([s.get("name") for s in high_entropy]) if high_entropy else "",
    "Zero CAPA matches" if len(capabilities) == 0 else "",
    "Non-standard section names: " + str([n for n in section_names if n and not n.startswith(".text") and not n.startswith(".data") and not n.startswith(".rdata") and not n.startswith(".bss") and not n.startswith(".rsrc") and not n.startswith(".reloc") and not n.startswith(".pdata") and len(n) > 0]) if any(n for n in section_names if n and not n.startswith((".text",".data",".rdata",".bss",".rsrc",".reloc",".pdata","_RDATA"))) else "",
    "Known packer signatures: " + str(detected_packers) if detected_packers else "",
    "Very few strings for file size" if strings.get("total_count",0) < 200 and filesize > 500000 else ""
]).replace(", ,","").strip(", ")}

═══════════════════════════════════════════════════════════
ANALYSIS MANDATE
═══════════════════════════════════════════════════════════

ABSOLUTE RULES — NEVER VIOLATE UNDER ANY CIRCUMSTANCES:
1. PACKED BINARY WITH HIGH ENTROPY = NEVER BENIGN. A legitimate packed binary is still suspicious. Malware with certificate strings inside a packed blob is still malicious.
2. {mal} VT engines flag this as malicious. This is your baseline. Override only with SPECIFIC TECHNICAL EVIDENCE, not absence of evidence.
3. DigiCert/certificate OCSP URLs in a PACKED binary with HIGH ENTROPY sections = stolen/embedded certificate artifact, NOT proof of legitimacy. This is a known malware evasion technique.
4. Zero strings + zero CAPA + high entropy = the real payload is HIDDEN. Do not confuse inability to analyze with cleanliness.
5. If you recognize the packer or family, NAME IT with confidence.
6. If evidence is contradictory, say so explicitly and explain the contradiction.
7. Confidence calibration: HIGH = multiple corroborating indicators. MEDIUM = some indicators, some uncertainty. LOW = limited evidence, significant uncertainty.
8. Every single claim MUST cite specific evidence from the tool output above.
9. Minimum 1500 words across both reports combined.
10. The technical report must be detailed enough that an IR analyst can act on it immediately.

Now produce both reports:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT A — EXECUTIVE SUMMARY (NON-TECHNICAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Audience: CEO, CFO, Legal, HR, non-technical management
Style: Plain English, no jargon, use analogies where helpful
Length: 4-5 paragraphs + action items

[EXECUTIVE_START]
THREAT LEVEL: [CRITICAL/HIGH/MEDIUM/LOW]
VERDICT: [MALICIOUS/SUSPICIOUS/BENIGN]

[Paragraph 1: What is this file and where might it have come from?]

[Paragraph 2: What is it capable of doing to our organization? Use plain language — "steal passwords", "lock all your files", "spy on employees", etc.]

[Paragraph 3: How confident are we in this assessment and why?]

[Paragraph 4: What is the potential business impact if this executed?]

IMMEDIATE ACTIONS REQUIRED:
1. [specific plain English action]
2. [specific plain English action]
3. [specific plain English action]
4. [specific plain English action]
[EXECUTIVE_END]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPORT B — FULL TECHNICAL ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Audience: SOC analysts, IR team, threat intel, malware researchers
Style: Full technical depth, cite evidence for every claim
Length: Comprehensive — cover every section fully

[TECHNICAL_START]

[1] VERDICT & CLASSIFICATION
VERDICT: [MALICIOUS/SUSPICIOUS/BENIGN]
Confidence: [HIGH/MEDIUM/LOW]
Threat Type: [specific — ransomware/RAT/stealer/loader/dropper/wiper/backdoor/PUP/benign]
Suspected Family: [name if identifiable, UNKNOWN if not]
Suspected Packer/Crypter: [name if identifiable, UNKNOWN if not]
Threat Actor Attribution: [APT group / cybercriminal group if TTPs match, UNKNOWN if not]
Motivation: [financial/espionage/destruction/hacktivism/unknown]
VT Automated Verdict: {vt_verdict} ({mal}/{tot} = {det_pct:.1f}%)
ARIA Override: [YES/NO] — [if YES: specific technical evidence for override]

[2] EXECUTIVE TECHNICAL OVERVIEW
2-3 paragraphs summarizing the complete technical picture for a senior analyst. What is this sample, what does it do, how confident are you, and what does an IR team need to know immediately?

[3] STATIC ANALYSIS — DEEP DIVE

3a. PE HEADER ANALYSIS
Analyze every PE header field. What anomalies exist? What does the compile timestamp tell you (forged? recent? consistent with claimed software)? What does the machine type tell you about targeting? What does the image base tell you?

3b. SECTION ANALYSIS
For EVERY section, explain:
- What does this entropy value mean technically?
- What is the expected content based on name vs what entropy suggests?
- Is this consistent with legitimate software or packing?
- What specific packer/crypter signature does this match if any?

3c. IMPORT TABLE ANALYSIS
For every suspicious import, explain:
- What does this Windows API function do?
- What attack technique does it enable?
- What malware families commonly use this combination?
- Is this import combination a known fingerprint?

3d. STRING ANALYSIS
Analyze ALL interesting strings:
- What does each string cluster reveal about functionality?
- Certificate URLs: are these legitimate or packer/malware artifacts?
- Are there C2 indicators, hardcoded IPs, domains, URLs?
- Are there configuration artifacts, mutex names, registry keys?
- What does the overall string density tell us?

3e. PACKER/OBFUSCATION ANALYSIS
- Is this binary packed? What is your confidence level?
- Which specific packer/crypter does the evidence suggest?
- What is the packing strategy (single layer, multi-layer, VM-based)?
- How does this affect our analysis capabilities?
- What unpacking approach would you recommend?

3f. TIMESTAMP & AUTHENTICITY ANALYSIS
- Is the compile timestamp plausible?
- Signs of timestamp manipulation?
- Does the imphash match any known legitimate or malicious software?
- Digital signature analysis if applicable

[4] CAPABILITY ASSESSMENT
Based on ALL evidence — even with 0 CAPA matches, infer from imports, strings, entropy patterns:
For each category state: [CONFIRMED/LIKELY/POSSIBLE/NO EVIDENCE] + cite specific evidence

- Code injection / process hollowing
- Remote thread execution
- Network communication / C2 beaconing
- Data exfiltration
- Keylogging / input capture
- Credential theft
- Persistence mechanisms
- Defense evasion / anti-analysis / anti-sandbox
- Cryptographic operations (encryption/decryption)
- Lateral movement
- Privilege escalation
- Payload delivery / dropper behavior
- Ransomware / file encryption
- Rootkit / bootkit behavior

[5] MITRE ATT&CK MAPPING
For every applicable technique:
TID      | Technique                    | Sub-technique              | Evidence                              | Confidence
---------|------------------------------|----------------------------|---------------------------------------|----------
[Be exhaustive. Infer from imports and strings where CAPA returned nothing.]

[6] INDICATORS OF COMPROMISE
Format as complete IOC table:
Type       | Value                                                              | Context/Notes
-----------|--------------------------------------------------------------------|---------------
MD5        | {h.get("md5","N/A")}                                              | Primary file hash
SHA1       | {h.get("sha1","N/A")}                                             | Primary file hash
SHA256     | {h.get("sha256","N/A")}                                           | Primary file hash
Imphash    | {imphash}                                                          | Import hash — use for family clustering
ssdeep     | {ssdeep_hash}                                                      | Fuzzy hash — use for variant detection
Filename   | {report_data.get("filename","N/A")}                               | Observed filename
[Extract and add ALL URLs, IPs, domains, mutex names, registry paths, file paths, pipe names from strings]
[Note: many IOCs will be hidden inside packed payload — flag as HIDDEN_IN_PAYLOAD where applicable]

[7] THREAT INTELLIGENCE CONTEXT
- Does this imphash match known malware family builders?
- Does the ssdeep pattern match known malware clusters?
- Which threat actors use these specific TTPs?
- What campaigns does this binary resemble?
- Is this commodity crimeware, custom tool, or APT implant? Why?
- What is the likely infection vector? (phishing/drive-by/supply chain/lateral movement)
- What is the likely attacker motivation?
- Geographic targeting indicators if any

[8] RISK ASSESSMENT
Risk Level: [CRITICAL/HIGH/MEDIUM/LOW] — justify this rating

For each dimension rate [CRITICAL/HIGH/MEDIUM/LOW] and explain:
- Immediate system risk
- Data exfiltration risk
- Lateral movement potential
- Persistence risk
- Detection/removal difficulty
- Business continuity impact
- Regulatory/compliance impact (HIPAA/PCI/GDPR relevance if applicable)

Overall Risk Score: [X/10] with justification

[9] FALSE POSITIVE ANALYSIS
Systematically evaluate false positive probability:
- VT detection context: is {det_pct:.1f}% detection consistent with FP patterns?
- Technical indicators supporting FP: [list if any]
- Technical indicators against FP: [list]
- Conclusion: [X%] probability this is a false positive — justify

[10] ANALYSIS LIMITATIONS & CONFIDENCE
Be precise about what we cannot determine:
- What does packing conceal from static analysis?
- What specific questions would dynamic analysis answer?
- What additional context would change the assessment?
- Where is confidence lowest and why?
- What is the single biggest uncertainty in this analysis?

[11] RECOMMENDED ACTIONS
Priority-ordered, specific, actionable:
1. [IMMEDIATE — within 1 hour] specific action with tool/command
2. [IMMEDIATE — within 1 hour] specific action with tool/command
3. [SHORT TERM — within 24h] specific action with tool/command
4. [SHORT TERM — within 24h] specific action with tool/command
5. [INVESTIGATION] specific unpacking/dynamic analysis steps

[12] ANALYST NOTES
Expert observations that dont fit elsewhere. Anomalies that caught your attention. Threat actor intuition. Anything an analyst reading this tomorrow needs to know. Professional judgment calls you made and why.

[TECHNICAL_END]"""

        response = client.chat.completions.create(
            model=ARIA_MODEL,
            max_tokens=4000,
            messages=[{"role": "user", "content": full_prompt}]
        )

        raw = response.choices[0].message.content

        exec_report = ""
        tech_report = ""

        if "[EXECUTIVE_START]" in raw and "[EXECUTIVE_END]" in raw:
            exec_report = raw.split("[EXECUTIVE_START]")[1].split("[EXECUTIVE_END]")[0].strip()
        if "[TECHNICAL_START]" in raw and "[TECHNICAL_END]" in raw:
            tech_report = raw.split("[TECHNICAL_START]")[1].split("[TECHNICAL_END]")[0].strip()

        if not exec_report:
            exec_report = raw[:1500]
        if not tech_report:
            tech_report = raw[1500:]

        return {
            "executive_report": exec_report,
            "technical_report": tech_report,
            "full_response": raw,
            "model": ARIA_MODEL,
            "tokens_used": (response.usage.prompt_tokens + response.usage.completion_tokens) if response.usage else 0
        }
    except Exception as e:
        return {"error": str(e)}


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "2.0"})


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "no file provided"}), 400
    safe_name = secure_filename(f.filename) or "upload"
    path = os.path.join(INCOMING, safe_name)
    f.save(path)
    return jsonify({"saved": safe_name, "path": path})


@app.route("/files", methods=["GET"])
def list_files():
    files = os.listdir(INCOMING)
    return jsonify({"files": files})


@app.route("/analyze/static", methods=["POST"])
def static_analysis():
    # Consume scan credit for customers
    token = request.cookies.get('aria_session')
    if token:
        try:
            import db
            session = db.get_session(token)
            if session and session['role'] not in ('admin', 'analyst'):
                if not db.consume_credit(session['user_id'], 'scan'):
                    return jsonify({"error": "No scan credits remaining. Purchase more at /store"}), 403
                print(f"[CREDIT] Consumed scan credit for user_id={session['user_id']}")
        except Exception as e:
            print(f"[CREDIT] Error checking scan credit: {e}")

    data = request.json
    filename = data.get("filename")
    analyst_notes = data.get("analyst_notes", "").strip()
    filepath = os.path.join(INCOMING, filename)

    if not os.path.exists(filepath):
        return jsonify({"error": f"File not found: {filepath}"}), 404

    results = {"filename": filename, "analysis_time": time.time(), "analyst_notes": analyst_notes}

    # Phase 1 — Hashes & file type (must run first: cache key derived from content hash)
    h = compute_hashes(filepath)
    results["hashes"] = h
    results["size"] = h.get("size_bytes", 0)
    results["file_type"] = get_file_type(filepath)

    # Cache key: SHA256 of file content + hash of analyst notes
    # Different notes → different ARIA analysis → different cache entry
    _notes_key = hashlib.md5(analyst_notes.encode()).hexdigest()[:8]
    cache_key = h["sha256"] + "_" + _notes_key
    cached = load_cache(cache_key) or ANALYSIS_CACHE.get(cache_key)
    if cached:
        return jsonify(cached)

    # Phase 1.5 — UPX auto-unpack: if UPX packed, unpack and re-analyze the clean binary
    _upx_unpacked = False
    try:
        _upx_check = subprocess.run(["upx", "-t", filepath], capture_output=True, timeout=30)
        if _upx_check.returncode == 0 and b"[OK]" in _upx_check.stdout:
            _unpacked_path = filepath + ".unpacked"
            import shutil
            shutil.copy2(filepath, _unpacked_path)
            _upx_unpack = subprocess.run(["upx", "-d", _unpacked_path], capture_output=True, timeout=60)
            if _upx_unpack.returncode == 0:
                results["upx"] = {"packed": True, "unpacked": True,
                                  "original_size": h.get("size_bytes", 0),
                                  "unpacked_size": os.path.getsize(_unpacked_path)}
                filepath = _unpacked_path  # analyze the unpacked binary from here on
                _upx_unpacked = True
                app.logger.info(f"UPX unpacked: {filepath}")
            else:
                results["upx"] = {"packed": True, "unpacked": False,
                                  "error": _upx_unpack.stderr.decode(errors='ignore')[:200]}
        else:
            results["upx"] = {"packed": False}
    except FileNotFoundError:
        results["upx"] = {"packed": False, "note": "upx not installed"}
    except Exception as _upx_err:
        results["upx"] = {"packed": False, "error": str(_upx_err)[:200]}

    # Phase 2 — Strings
    s = get_strings(filepath)
    results["strings"] = {
        "total_count": s.get("total_count", 0),
        "interesting": s.get("interesting_strings", []),
        "all_strings": s.get("all_strings", [])
    }

    # Phase 3 — PE Analysis
    pe = analyze_pe(filepath)
    results["pe_info"] = {
        "is_pe": pe.get("is_pe", False),
        "machine": pe.get("machine_type", "N/A"),
        "compile_time": pe.get("compile_timestamp_human", "N/A"),
        "entrypoint": pe.get("entrypoint", "N/A"),
        "image_base": pe.get("image_base", "N/A"),
        "imphash": pe.get("imphash", "N/A"),
        "sections": [{
            "name": sec.get("name", "?"),
            "entropy": sec.get("entropy", 0),
            "raw_size": sec.get("size", 0),
            "virtual_size": sec.get("virtual_size", 0)
        } for sec in pe.get("sections", [])],
        "imports": pe.get("imports", []),
        "exports": pe.get("exports", []),
        "suspicious_imports": [i["dll"]+"::" +i["function"] if isinstance(i, dict) else str(i) for i in pe.get("suspicious_imports", [])],
        "rich_header": pe.get("rich_header", {"present": False}),
        "overlay": pe.get("overlay", {"present": False}),
        "authenticode": pe.get("authenticode", {"present": False}),
        "tls_callbacks": pe.get("tls_callbacks", {"present": False})
    }

    # Phase 4 — CAPA capabilities
    results["ghidra"] = run_ghidra(filepath)
    results["die"] = run_die(filepath)
    results["floss"] = run_floss(filepath)
    results["capa"] = run_capa(filepath)

    # Phase 5 — YARA
    y = run_yara(filepath)
    results["yara_matches"] = y.get("matches", [])

    # Phase 6 — VirusTotal hash lookup
    results["virustotal"] = check_virustotal(results["hashes"]["sha256"])

    # Phase 7 — ARIA AI Analysis
    results["aria"] = aria_analyze(results)

    # Phase 8 — Deterministic confidence scoring
    _conf = compute_confidence_score(results)
    results["confidence_score"]    = _conf["percent"]
    results["confidence_label"]    = _conf["label"]
    results["confidence_breakdown"] = _conf["breakdown"]

    # Phase 9 — IOC enrichment (AbuseIPDB + URLhaus)
    try:
        results["ioc_enrichment"] = enrich_iocs(results)
    except Exception as _ioc_err:
        results["ioc_enrichment"] = {"error": str(_ioc_err)[:200]}

    # Phase 10 — Auto-generate YARA detection rule
    try:
        results["generated_yara"] = generate_yara_rule(results)
    except Exception as _yara_err:
        results["generated_yara"] = None

    ANALYSIS_CACHE[cache_key] = results
    save_cache(cache_key, results)

    # ── Save to PostgreSQL ──
    try:
        import db as _db
        _user_id = None
        _token = request.cookies.get('aria_session')
        if _token:
            _sess = _db.get_session(_token)
            if _sess:
                _user_id = _sess.get('user_id')

        _score_data = results.get("confidence_score", {})
        _scan_id = _db.save_scan(
            sha256=results.get("sha256", ""),
            filename=results.get("filename", ""),
            filesize=results.get("size", 0),
            mime_type=results.get("magic", {}).get("mime", ""),
            verdict=_score_data.get("label", "unknown"),
            score=_score_data.get("total", 0),
            label=_score_data.get("label", ""),
            user_id=_user_id
        )
        if _scan_id:
            _db.save_findings(_scan_id, _score_data.get("breakdown", []))
            # Save IOCs if present
            _iocs = []
            _str_data = results.get("strings", {})
            if isinstance(_str_data, dict):
                for _ip in _str_data.get("ips", []):
                    _iocs.append({"type": "ip", "value": _ip, "context": "strings"})
                for _url in _str_data.get("urls", []):
                    _iocs.append({"type": "url", "value": _url, "context": "strings"})
                for _dom in _str_data.get("domains", []):
                    _iocs.append({"type": "domain", "value": _dom, "context": "strings"})
            if _iocs:
                _db.save_iocs(_scan_id, _iocs)
            results["scan_id"] = _scan_id
    except Exception as _db_err:
        results["db_note"] = f"DB save skipped: {str(_db_err)[:100]}"

    return jsonify(results)


@app.route("/analyze/hash", methods=["POST"])
def analyze_hash():
    data = request.json
    file_hash = data.get("hash")
    if not file_hash:
        return jsonify({"error": "hash required"}), 400
    return jsonify({"hash": file_hash, "virustotal": check_virustotal(file_hash)})



# ── PDF Report Generation ──────────────────────────────────────────────────────
import sys
import tempfile
import datetime

@app.route("/generate_pdf", methods=["POST"])
def generate_pdf():
    """
    Accepts the full analysis results JSON and returns a PDF report.
    Expected JSON body: the same structure returned by /analyze/static + aria_report field.
    """
    # Consume report credit for customers
    token = request.cookies.get('aria_session')
    if token:
        try:
            import db
            session = db.get_session(token)
            if session and session['role'] not in ('admin', 'analyst'):
                if not db.consume_credit(session['user_id'], 'report'):
                    return jsonify({"error": "No report credits remaining. Purchase more at /store"}), 403
                print(f"[CREDIT] Consumed report credit for user_id={session['user_id']}")
        except Exception as e:
            print(f"[CREDIT] Error checking report credit: {e}")
    try:
        sys.path.insert(0, BASE_DIR)
        import importlib
        import aria_report as _aria_mod
        importlib.reload(_aria_mod)
        build_report_from_data = _aria_mod.build_report_from_data

        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON data received"}), 400

        # Add generation timestamp if not present
        if 'generated_at' not in data:
            data['generated_at'] = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        # Write to temp file
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
            tmp_path = tmp.name

        build_report_from_data(data, tmp_path)

        with open(tmp_path, 'rb') as f:
            pdf_bytes = f.read()

        import os
        os.unlink(tmp_path)

        filename = 'ARIA_Report_' + data.get('filename', 'sample').replace('.', '_') + '_' + \
                   datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S') + '.pdf'

        from flask import send_file
        import io
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        import traceback
        tb = traceback.format_exc(); app.logger.error(tb); return jsonify({"error": str(e), "trace": tb}), 500


# ══════════════════════════════════════════════════════════════════════════════
# STIX 2.1 EXPORT — structured threat intelligence output
# ══════════════════════════════════════════════════════════════════════════════
import uuid as _uuid
import datetime as _dt

def _stix_id(stype):
    return f"{stype}--{_uuid.uuid4()}"

def build_stix_bundle(data):
    """Convert ARIA analysis results to a STIX 2.1 bundle."""
    now = _dt.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
    objects = []

    hashes = data.get('hashes', {})
    sha256 = hashes.get('sha256', '')
    md5 = hashes.get('md5', '')
    sha1 = hashes.get('sha1', '')
    filename = data.get('filename', 'unknown')

    # 1) File observable
    file_id = _stix_id('file')
    file_obj = {
        "type": "file", "spec_version": "2.1", "id": file_id,
        "name": filename,
        "hashes": {}
    }
    if sha256: file_obj["hashes"]["SHA-256"] = sha256
    if md5: file_obj["hashes"]["MD5"] = md5
    if sha1: file_obj["hashes"]["SHA-1"] = sha1
    size = data.get('size', hashes.get('size_bytes', 0))
    if size: file_obj["size"] = size
    objects.append(file_obj)

    # 2) Malware SDO
    aria = data.get('aria', {})
    aria_text = (aria.get('full_response') or aria.get('technical_report') or '')
    # Detect families same way as aria_report.py
    _fam_map = {
        'RAT': [r'remote.access.trojan', r'\brat\b(?!io)'],
        'INFOSTEALER': [r'info.?stealer', r'credential.stealer'],
        'KEYLOGGER': [r'keylog'],
        'RANSOMWARE': [r'(?:this (?:sample|file|malware|binary)|it)\s+is\s+(?:a\s+)?ransomware'],
        'BACKDOOR': [r'\bbackdoor\b'],
        'DROPPER': [r'(?:is|acts? as) a dropper'],
        'SPYWARE': [r'\bspyware\b'],
        'BANKER': [r'banking.trojan', r'\bbanker\b'],
    }
    _aria_low = aria_text.lower()
    families = [f for f, pats in _fam_map.items() if any(re.search(p, _aria_low) for p in pats)]
    if 'RAT' in families and 'BACKDOOR' not in families:
        families.append('BACKDOOR')
    if not families: families = ['unknown']

    _stix_mtype = {
        'RAT': 'remote-access-trojan', 'BACKDOOR': 'backdoor', 'RANSOMWARE': 'ransomware',
        'KEYLOGGER': 'keylogger', 'SPYWARE': 'spyware', 'DROPPER': 'dropper',
        'INFOSTEALER': 'trojan', 'BANKER': 'trojan',
    }
    malware_types = list(set(_stix_mtype.get(f, 'trojan') for f in families))

    malware_id = _stix_id('malware')
    malware_obj = {
        "type": "malware", "spec_version": "2.1", "id": malware_id,
        "created": now, "modified": now,
        "name": filename,
        "description": f"ARIA analysis: {'/'.join(families)} — confidence {data.get('confidence_score', 0)}/100",
        "malware_types": malware_types,
        "is_family": False,
        "sample_refs": [file_id]
    }
    objects.append(malware_obj)

    # 3) Indicators — one per hash
    indicator_ids = []
    for hash_type, hash_val in [("SHA-256", sha256), ("MD5", md5), ("SHA-1", sha1)]:
        if not hash_val or hash_val == 'N/A': continue
        ind_id = _stix_id('indicator')
        indicator_ids.append(ind_id)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": now, "modified": now,
            "name": f"{filename} — {hash_type}",
            "description": f"File hash indicator from ARIA static analysis",
            "pattern": f"[file:hashes.'{hash_type}' = '{hash_val}']",
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
            "labels": [f.lower() for f in families]
        })

    # 4) Network indicators from strings
    strings_data = data.get('strings', {})
    all_strings = strings_data.get('interesting', []) + strings_data.get('all_strings', [])[:200]
    _url_re = re.compile(r'https?://[^\s\'"<>]{4,120}')
    _ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _seen_net = set()
    for s in all_strings:
        for url in _url_re.findall(s):
            if url not in _seen_net and not any(x in url.lower() for x in ['microsoft.com', 'windows.com', 'digicert', 'verisign', 'symantec']):
                _seen_net.add(url)
                ind_id = _stix_id('indicator')
                indicator_ids.append(ind_id)
                objects.append({
                    "type": "indicator", "spec_version": "2.1", "id": ind_id,
                    "created": now, "modified": now,
                    "name": f"URL: {url[:80]}",
                    "pattern": f"[url:value = '{url}']",
                    "pattern_type": "stix", "valid_from": now,
                    "indicator_types": ["malicious-activity"]
                })
        for ip in _ip_re.findall(s):
            if ip not in _seen_net and not ip.startswith(('0.', '127.', '255.', '10.', '192.168.', '224.')):
                _seen_net.add(ip)
                ind_id = _stix_id('indicator')
                indicator_ids.append(ind_id)
                objects.append({
                    "type": "indicator", "spec_version": "2.1", "id": ind_id,
                    "created": now, "modified": now,
                    "name": f"IP: {ip}",
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix", "valid_from": now,
                    "indicator_types": ["malicious-activity"]
                })

    # 5) Attack patterns from CAPA MITRE mappings
    capa_data = data.get('capa', {})
    _mitre_seen = set()
    for cap in capa_data.get('capabilities', []):
        atk = cap.get('attack', []) if isinstance(cap, dict) else []
        for a in atk:
            tid = a.get('id', '') if isinstance(a, dict) else ''
            if tid and tid not in _mitre_seen:
                _mitre_seen.add(tid)
                ap_id = _stix_id('attack-pattern')
                objects.append({
                    "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
                    "created": now, "modified": now,
                    "name": a.get('technique', tid),
                    "external_references": [{"source_name": "mitre-attack", "external_id": tid}]
                })
                # Relationship: malware uses attack-pattern
                objects.append({
                    "type": "relationship", "spec_version": "2.1", "id": _stix_id('relationship'),
                    "created": now, "modified": now,
                    "relationship_type": "uses",
                    "source_ref": malware_id, "target_ref": ap_id
                })

    # 6) Relationships: indicators indicate malware
    for ind_id in indicator_ids:
        objects.append({
            "type": "relationship", "spec_version": "2.1", "id": _stix_id('relationship'),
            "created": now, "modified": now,
            "relationship_type": "indicates",
            "source_ref": ind_id, "target_ref": malware_id
        })

    return {
        "type": "bundle", "id": _stix_id('bundle'),
        "objects": objects
    }

@app.route("/export/stix", methods=["POST"])
def export_stix():
    """Export analysis results as STIX 2.1 JSON bundle."""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON data"}), 400
        bundle = build_stix_bundle(data)
        resp = jsonify(bundle)
        resp.headers['Content-Type'] = 'application/stix+json;version=2.1'
        return resp
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ══════════════════════════════════════════════════════════════════════════════
# THREAT INTEL FEED CORRELATION — AbuseIPDB + URLhaus
# ══════════════════════════════════════════════════════════════════════════════
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"

def check_abuseipdb(ip):
    """Check an IP against AbuseIPDB. Returns abuse confidence score 0-100."""
    if not ABUSEIPDB_KEY:
        return {"ip": ip, "checked": False, "note": "ABUSEIPDB_API_KEY not set"}
    try:
        resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": ip, "maxAgeInDays": 90},
                            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                            timeout=10)
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {"ip": ip, "checked": True, "abuse_score": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode", "??"), "isp": d.get("isp", ""),
                    "total_reports": d.get("totalReports", 0), "is_tor": d.get("isTor", False)}
        return {"ip": ip, "checked": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"ip": ip, "checked": False, "error": str(e)[:120]}

def check_urlhaus(url_or_host):
    """Check a URL or host against URLhaus malware URL database."""
    try:
        # Try as URL first, then as host
        resp = requests.post(URLHAUS_API + "/url/", data={"url": url_or_host}, timeout=10)
        if resp.status_code == 200:
            d = resp.json()
            if d.get("query_status") == "ok":
                return {"query": url_or_host, "checked": True, "found": True,
                        "threat": d.get("threat", ""), "status": d.get("url_status", ""),
                        "tags": d.get("tags", []), "date_added": d.get("date_added", "")}
        # Try as host
        host = re.sub(r'^https?://', '', url_or_host).split('/')[0].split(':')[0]
        resp2 = requests.post(URLHAUS_API + "/host/", data={"host": host}, timeout=10)
        if resp2.status_code == 200:
            d2 = resp2.json()
            urls = d2.get("urls", [])
            if urls:
                return {"query": host, "checked": True, "found": True,
                        "url_count": d2.get("url_count", len(urls)),
                        "first_seen": urls[0].get("date_added", "") if urls else ""}
        return {"query": url_or_host, "checked": True, "found": False}
    except Exception as e:
        return {"query": url_or_host, "checked": False, "error": str(e)[:120]}

def enrich_iocs(data):
    """Extract and enrich network IOCs from analysis results."""
    results = {"ips": [], "urls": [], "enriched_at": _dt.datetime.utcnow().isoformat() + "Z"}

    strings_data = data.get('strings', {})
    all_strings = strings_data.get('interesting', []) + strings_data.get('all_strings', [])[:300]
    combined = '\n'.join(all_strings)

    # Extract IPs (skip private/reserved)
    _ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    _seen_ip = set()
    for ip in _ip_re.findall(combined):
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts) and ip not in _seen_ip:
            if not ip.startswith(('0.', '127.', '255.', '10.', '192.168.', '172.16.', '172.17.',
                                  '172.18.', '172.19.', '172.2', '172.30.', '172.31.', '224.', '169.254.')):
                _seen_ip.add(ip)
                results["ips"].append(check_abuseipdb(ip))

    # Extract URLs
    _url_re = re.compile(r'https?://[^\s\'"<>]{4,200}')
    _benign = {'microsoft.com', 'windows.com', 'digicert.com', 'verisign.com', 'google.com',
               'googleapis.com', 'gstatic.com', 'symantec.com', 'thawte.com', 'w3.org'}
    _seen_url = set()
    for url in _url_re.findall(combined):
        host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0].lower()
        if url not in _seen_url and not any(b in host for b in _benign):
            _seen_url.add(url)
            results["urls"].append(check_urlhaus(url))

    return results

@app.route("/enrich/iocs", methods=["POST"])
def enrich_iocs_endpoint():
    """Enrich extracted IOCs against AbuseIPDB and URLhaus."""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON data"}), 400
        enriched = enrich_iocs(data)
        return jsonify(enriched)
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


# ══════════════════════════════════════════════════════════════════════════════
# AUTO YARA RULE GENERATOR — create detection signatures from analyzed samples
# ══════════════════════════════════════════════════════════════════════════════
def generate_yara_rule(data):
    """Generate a YARA detection rule from analysis results."""
    hashes = data.get('hashes', {})
    sha256 = hashes.get('sha256', '')
    md5 = hashes.get('md5', '')
    imphash = data.get('pe_info', {}).get('imphash', '')
    filename = data.get('filename', 'unknown').replace('.', '_').replace('-', '_')
    score = data.get('confidence_score', 0)
    size = data.get('size', hashes.get('size_bytes', 0))

    # Sanitize rule name
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', filename)
    if rule_name[0].isdigit():
        rule_name = '_' + rule_name

    # Collect unique strings for detection
    strings_data = data.get('strings', {})
    interesting = strings_data.get('interesting', [])

    # Pick the best unique strings (C2 URLs, paths, mutexes, commands)
    _high_value_kw = ['http://', 'https://', 'ftp://', '.onion', 'cmd /c', 'powershell',
                      'HKEY_', '\\AppData\\', 'Mozilla/5.0', 'User-Agent:', '/c2/',
                      'POST', 'GET', 'beacon', 'mutex', 'pipe']
    high_value = []
    general = []
    for s in interesting:
        s_clean = s.strip()
        if len(s_clean) < 8 or len(s_clean) > 200: continue
        if any(kw.lower() in s_clean.lower() for kw in _high_value_kw):
            high_value.append(s_clean)
        elif len(s_clean) >= 12:
            general.append(s_clean)

    # Deduplicate and limit
    high_value = list(dict.fromkeys(high_value))[:10]
    general = list(dict.fromkeys(general))[:10]

    # Build PE section entropy conditions
    pe_info = data.get('pe_info', {})
    sections = pe_info.get('sections', [])
    high_entropy_sections = [s for s in sections if float(s.get('entropy', 0)) > 7.0]

    # Build YARA rule
    lines = []
    lines.append(f'rule ARIA_{rule_name} {{')
    lines.append(f'    meta:')
    lines.append(f'        description = "Auto-generated by ARIA for {data.get("filename", "unknown")}"')
    lines.append(f'        author = "ARIA Automated Analysis"')
    lines.append(f'        date = "{_dt.datetime.utcnow().strftime("%Y-%m-%d")}"')
    lines.append(f'        confidence = "{score}/100"')
    if sha256: lines.append(f'        sha256 = "{sha256}"')
    if md5: lines.append(f'        md5 = "{md5}"')
    if imphash and imphash != 'N/A': lines.append(f'        imphash = "{imphash}"')
    lines.append(f'        severity = "{"HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"}"')
    lines.append(f'')

    # Strings section
    has_strings = high_value or general
    if has_strings:
        lines.append(f'    strings:')
        idx = 0
        for s in high_value:
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'        $hv{idx} = "{escaped}" nocase')
            idx += 1
        for s in general:
            escaped = s.replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f'        $gs{idx} = "{escaped}"')
            idx += 1
        lines.append(f'')

    # Condition
    lines.append(f'    condition:')
    conditions = []

    # File size range (±50%)
    if size and size > 0:
        low = max(1024, int(size * 0.5))
        high = int(size * 1.5)
        conditions.append(f'filesize > {low} and filesize < {high}')

    # Imphash match (strongest single indicator)
    if imphash and imphash != 'N/A':
        conditions.append(f'pe.imphash() == "{imphash}"')

    # String matching
    if has_strings:
        total_str = len(high_value) + len(general)
        threshold = max(2, total_str // 3)
        if high_value and general:
            hv_count = len(high_value)
            conditions.append(f'(1 of ($hv*) and {threshold} of them)')
        elif total_str > 2:
            conditions.append(f'{threshold} of them')
        else:
            conditions.append('any of them')

    # High entropy section detection
    if high_entropy_sections:
        sec_name = high_entropy_sections[0].get('name', '.text')
        conditions.append(f'// High entropy section: {sec_name} ({high_entropy_sections[0].get("entropy", 0):.2f})')

    if not conditions:
        conditions.append(f'uint16(0) == 0x5A4D  // PE magic bytes')

    indent = '        '
    if len(conditions) == 1:
        lines.append(f'{indent}{conditions[0]}')
    else:
        # Filter out comments from the 'and' chain
        real_conds = [c for c in conditions if not c.strip().startswith('//')]
        comment_conds = [c for c in conditions if c.strip().startswith('//')]
        lines.append(f'{indent}' + f' and\n{indent}'.join(real_conds))
        for cc in comment_conds:
            lines.append(f'{indent}{cc}')

    lines.append('}')

    return '\n'.join(lines)

@app.route("/generate/yara", methods=["POST"])
def generate_yara_endpoint():
    """Generate a YARA detection rule from analysis results."""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON data"}), 400
        rule = generate_yara_rule(data)
        return jsonify({"rule": rule, "format": "yara"})
    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route('/test')
def serve_test():
    """Analysis platform — requires auth. Admin/analyst get full access, customers need scan credit."""
    token = request.cookies.get('aria_session')
    if not token:
        return '<script>alert("Please sign in to access the analysis platform.");window.location.href="/";</script>'
    try:
        import db
        session = db.get_session(token)
        if not session:
            return '<script>alert("Session expired. Please sign in again.");window.location.href="/";</script>'
        if session['role'] in ('admin', 'analyst'):
            return send_from_directory(BASE_DIR, 'openclaw_test.html')
        # Customer — check if they have any active service (any purchase grants access)
        has_purchase = db.query_one(
            "SELECT id FROM user_services WHERE user_id = %s AND status = 'active'",
            (session['user_id'],))
        if has_purchase:
            return send_from_directory(BASE_DIR, 'openclaw_test.html')
        return '<script>alert("You need to purchase a product or service to access the analysis platform.");window.location.href="/store";</script>'
    except Exception:
        # DB down — only allow if we can't verify (fail open for admin)
        return '<script>alert("Please sign in to access the analysis platform.");window.location.href="/";</script>'

@app.route("/")
def serve_landing():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/store")
def serve_store():
    return send_from_directory(BASE_DIR, "store.html")

@app.route("/portal")
def serve_portal():
    return send_from_directory(BASE_DIR, "portal.html")

@app.route("/dashboard")
def serve_ui():
    return send_from_directory(BASE_DIR, "aria-lab.html")

@app.route("/api/download/<product_id>")
@require_auth
def api_download(product_id):
    """Serve digital product downloads or redirect to service."""
    product_id = re.sub(r'[^a-z]', '', product_id)
    try:
        import db
        if not db.user_has_download(request.user['user_id'], product_id):
            return jsonify({"error": "You haven't purchased this product"}), 403
    except Exception:
        pass

    # Report → redirect to analysis platform where they generate their own PDF
    if product_id == "report":
        return '<html><head><meta http-equiv="refresh" content="0;url=/test"></head><body>Redirecting to Analysis Platform to generate your report...</body></html>'

    # YARA → serve the rules pack from capa-rules directory
    if product_id == "yara":
        rules_dir = os.path.join(BASE_DIR, "capa-rules")
        # Try serving a zip if it exists, otherwise serve the rules directory listing
        zip_path = os.path.join(BASE_DIR, "downloads", "ARIA_YARA_Rules.zip")
        if os.path.exists(zip_path):
            return send_from_directory(os.path.join(BASE_DIR, "downloads"), "ARIA_YARA_Rules.zip", mimetype="application/zip")
        # Generate zip on the fly from yara rules
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            yara_dir = os.path.join(BASE_DIR, "yara-rules") if os.path.exists(os.path.join(BASE_DIR, "yara-rules")) else rules_dir
            if os.path.exists(yara_dir):
                for root, dirs, files in os.walk(yara_dir):
                    for f in files:
                        if f.endswith(('.yar', '.yara', '.yml', '.yaml')):
                            fpath = os.path.join(root, f)
                            arcname = os.path.relpath(fpath, yara_dir)
                            zf.write(fpath, arcname)
            # Add a readme
            zf.writestr("README.txt", "ARIA YARA Rule Pack\n\nThese rules detect common malware families, packers, and suspicious behaviors.\nImport into your YARA-compatible scanner or SIEM.\n\nARIA Security - 2026\n")
        buf.seek(0)
        resp = make_response(buf.read())
        resp.headers['Content-Type'] = 'application/zip'
        resp.headers['Content-Disposition'] = 'attachment; filename=ARIA_YARA_Rules.zip'
        return resp

    return jsonify({"error": "Unknown product"}), 404


# ══════════════════════════════════════
#  E-COMMERCE — Orders & Cart
# ══════════════════════════════════════

@app.route("/api/order", methods=["POST"])
@require_auth
@rate_limit(max_req=10, window=60)
def api_create_order():
    """Create order after PayPal payment capture."""
    data = request.get_json(force=True)
    items = data.get("items", [])
    paypal_order_id = str(data.get("paypal_order_id", "")).strip()[:64]
    paypal_payer = str(data.get("paypal_payer", "")).strip()[:128]
    paypal_status = str(data.get("paypal_status", "")).strip()[:32]
    billing_email = str(data.get("billing_email", "")).strip()[:128]

    if not items:
        return jsonify({"error": "No items in order"}), 400
    if not paypal_order_id:
        return jsonify({"error": "PayPal payment required"}), 400

    valid_products = {
        "report": {"name": "Threat Intel Report", "price": 49, "type": "download"},
        "yara": {"name": "YARA Rule Pack", "price": 199, "type": "download"},
        "ioc": {"name": "IOC Feed Subscription", "price": 99, "type": "service"},
        "scan": {"name": "Malware Analysis Scan", "price": 149, "type": "service"},
        "chatbot": {"name": "AI Threat Chatbot", "price": 79, "type": "service"},
        "agentic": {"name": "Agentic Workflow Pipeline", "price": 499, "type": "service"},
    }

    validated_items = []
    calc_total = 0
    has_service = False
    downloads = []
    for item in items:
        pid = item.get("id", "")
        if pid not in valid_products:
            return jsonify({"error": f"Invalid product: {pid}"}), 400
        p = valid_products[pid]
        validated_items.append({"id": pid, "name": p["name"], "price": p["price"], "type": p["type"]})
        calc_total += p["price"]
        if p["type"] == "service":
            has_service = True
        if p["type"] == "download":
            downloads.append({"name": p["name"], "url": f"/api/download/{pid}", "description": f"Digital delivery - {p['name']}"})

    order_id = f"ORD-{secrets.token_hex(4).upper()}"
    user_id = request.user.get('user_id')
    api_key = None
    access_level = None

    try:
        import db
        print(f"[ORDER] Creating order {order_id} for user_id={user_id}, items={len(validated_items)}, total=${calc_total}")
        db.create_order(order_id, request.user.get('username', ''), billing_email or paypal_payer,
                        '', validated_items, calc_total, paypal_order_id, paypal_status, user_id)
        print(f"[ORDER] Order {order_id} saved to DB")

        # Provision services and downloads
        for item in validated_items:
            db.provision_service(user_id, item["id"], item["name"])
            print(f"[ORDER] Provisioned service: {item['name']} for user_id={user_id}")
            if item["type"] == "download":
                db.provision_download(user_id, item["id"], item["name"])
                print(f"[ORDER] Provisioned download: {item['name']} for user_id={user_id}")

        # Every purchase grants platform access (scan service)
        db.provision_service(user_id, "scan", "Malware Analysis Scan")
        print(f"[ORDER] Granted platform access for user_id={user_id}")

        # Generate API key for every customer
        api_key = db.get_or_create_apikey(user_id)
        access_level = "full" if any(i["id"] == "agentic" for i in validated_items) else "standard"
        print(f"[ORDER] API key generated for user_id={user_id}")

    except Exception as e:
        print(f"[ORDER] ERROR: {e}")
        import traceback
        traceback.print_exc()

    result = {
        "ok": True,
        "order_id": order_id,
        "paypal_order_id": paypal_order_id,
        "total": calc_total,
    }
    if api_key:
        result["api_key"] = api_key
        result["access_level"] = access_level
    if downloads:
        result["downloads"] = downloads
    return jsonify(result)


@app.route("/api/orders")
@require_admin
def api_list_orders():
    """Admin: list all orders."""
    try:
        import db
        orders = db.get_orders(100)
        for o in orders:
            if 'created_at' in o and o['created_at']:
                o['created_at'] = o['created_at'].isoformat()
        return jsonify({"orders": orders})
    except Exception as e:
        return jsonify({"orders": [], "error": str(e)})


# ══════════════════════════════════════
#  AI CHATBOT — Threat Intelligence
# ══════════════════════════════════════

THREAT_KB = {
    "ransomware": "Ransomware encrypts victim files and demands payment for decryption keys. Common families: LockBit, BlackCat (ALPHV), Cl0p, Royal. MITRE ATT&CK: T1486 (Data Encrypted for Impact). Defense: offline backups, network segmentation, email filtering, endpoint detection.",
    "trojan": "Trojans disguise as legitimate software to gain access. Common types: RAT (Remote Access Trojan), banking trojans, info-stealers. MITRE ATT&CK: T1204 (User Execution). Defense: application whitelisting, user training, sandboxed execution.",
    "phishing": "Phishing uses social engineering to steal credentials or deliver malware. Types: spear-phishing (T1566.001), whaling, vishing. Defense: DMARC/DKIM/SPF email auth, user awareness training, URL filtering.",
    "apt": "Advanced Persistent Threats are state-sponsored groups conducting long-term espionage. Notable APTs: APT28 (Russia), APT41 (China), Lazarus (DPRK). MITRE ATT&CK: multiple techniques across kill chain. Defense: threat hunting, EDR, network monitoring, zero trust.",
    "c2": "Command and Control (C2) infrastructure allows attackers to communicate with compromised systems. MITRE ATT&CK: T1071 (Application Layer Protocol). Common C2 frameworks: Cobalt Strike, Sliver, Brute Ratel. Defense: DNS monitoring, beacon detection, egress filtering.",
    "ioc": "Indicators of Compromise include file hashes (MD5/SHA256), IP addresses, domains, URLs, registry keys, and mutex names. Use STIX/TAXII for sharing. ARIA extracts IOCs automatically during analysis.",
    "yara": "YARA rules identify malware by matching patterns in file content. Syntax: rule name { strings: $s1 = \"pattern\" condition: $s1 }. ARIA includes 47+ active rules covering major malware families.",
    "mitre": "MITRE ATT&CK is a knowledge base of adversary tactics and techniques. 14 tactics from Reconnaissance to Impact. Use it to map detections, identify gaps, and communicate threats. ARIA maps findings to ATT&CK automatically.",
    "zero-day": "Zero-day vulnerabilities are unknown to the vendor with no available patch. They are highly valuable on exploit markets. Defense: virtual patching, behavioral detection, network segmentation, threat intel feeds.",
    "malware": "Malware is malicious software including viruses, worms, trojans, ransomware, spyware, and adware. Analysis types: static (no execution), dynamic (sandboxed execution), hybrid. ARIA performs static analysis with AI enrichment.",
    "cve": "CVE (Common Vulnerabilities and Exposures) is a standardized identifier for security flaws. Format: CVE-YYYY-NNNNN. Check NIST NVD for details and CVSS scores. Prioritize by exploitability and asset exposure.",
    "incident": "Incident response phases: 1) Preparation, 2) Identification, 3) Containment, 4) Eradication, 5) Recovery, 6) Lessons learned. ARIA supports phases 2-4 with automated analysis and IOC extraction.",
    "sandbox": "Sandbox evasion techniques include: sleep timers, VM detection, anti-debug checks, environment fingerprinting. MITRE ATT&CK: T1497 (Virtualization/Sandbox Evasion). ARIA detects these behaviors during static analysis.",
    "persistence": "Persistence mechanisms allow malware to survive reboots. Common: registry run keys (T1547.001), scheduled tasks (T1053), services (T1543), startup folder (T1547.001). ARIA flags these in analysis reports.",
}

@app.route("/api/chat", methods=["POST"])
@rate_limit(max_req=30, window=60)
def api_chat():
    """AI chatbot for threat intelligence queries."""
    data = request.get_json(force=True)
    message = str(data.get("message", "")).strip()[:500]

    if not message:
        return jsonify({"response": "Please ask a question about threat intelligence, malware, or security."})

    msg_lower = message.lower()

    # Check for greetings
    greetings = ["hello", "hi", "hey", "help", "what can you do"]
    if any(g in msg_lower for g in greetings):
        return jsonify({"response": "I'm ARIA's AI threat intelligence assistant. I can help with:\n- Malware families & analysis\n- MITRE ATT&CK techniques\n- IOC lookups & enrichment\n- YARA rule guidance\n- Incident response steps\n- CVE information\n- Ransomware, APTs, phishing\n\nWhat would you like to know?"})

    # Try to match against knowledge base
    best_match = None
    best_score = 0
    for key, response in THREAT_KB.items():
        # Count keyword matches
        score = 0
        if key in msg_lower:
            score += 10
        words = key.replace("-", " ").split()
        for w in words:
            if w in msg_lower:
                score += 3
        if score > best_score:
            best_score = score
            best_match = response

    # Check for specific patterns
    if "how" in msg_lower and "protect" in msg_lower:
        return jsonify({"response": "Key protection strategies:\n1. Endpoint Detection & Response (EDR)\n2. Network segmentation & zero trust\n3. Regular patching & vulnerability scanning\n4. Email security (DMARC/DKIM/SPF)\n5. Offline backup strategy (3-2-1 rule)\n6. User security awareness training\n7. Threat intelligence feeds & IOC monitoring\n8. Incident response plan & tabletop exercises\n\nARIA helps with automated threat detection and IOC enrichment."})

    if "scan" in msg_lower or "analyze" in msg_lower or "upload" in msg_lower:
        return jsonify({"response": "To analyze a file with ARIA:\n1. Sign in to the platform\n2. Go to the Analysis page (/test)\n3. Upload your suspicious file\n4. ARIA performs: PE parsing, entropy analysis, YARA matching, CAPA detection, AI classification, and IOC extraction\n5. Download your PDF report\n\nNeed an on-demand scan? Check our store for analysis credits."})

    if any(w in msg_lower for w in ["price", "cost", "buy", "purchase", "plan"]):
        return jsonify({"response": "ARIA offers:\n\nProducts:\n- Threat Intel Reports: $49/report\n- YARA Rule Packs: $199/pack\n- IOC Feed Subscription: $99/month\n\nServices:\n- Malware Analysis: $149/scan\n- AI Threat Chatbot: $79/month\n- Agentic Workflow: $499/month\n\nVisit /store to purchase."})

    # Try DB for scan stats
    if any(w in msg_lower for w in ["stats", "status", "dashboard", "how many"]):
        try:
            import db
            scans = db.get_scan_count()
            threats = db.get_threat_count()
            iocs = db.get_ioc_count()
            return jsonify({"response": f"ARIA Platform Status:\n- Total scans: {scans}\n- Threats detected: {threats}\n- IOCs cataloged: {iocs}\n- Engine: Online\n- Database: Connected\n\nAll systems operational."})
        except Exception:
            return jsonify({"response": "ARIA Platform Status:\n- Engine: Online\n- Database: Checking...\n\nUse /test to run an analysis."})

    if best_match and best_score >= 3:
        return jsonify({"response": best_match})

    # Default response
    return jsonify({"response": "I can help with threat intelligence topics including:\n- Malware types (ransomware, trojans, APTs)\n- MITRE ATT&CK framework\n- IOC analysis & enrichment\n- YARA rule creation\n- Incident response\n- CVE lookups\n- Security best practices\n\nTry asking about a specific threat or technique."})

if __name__ == "__main__":
    # Initialize database connection and default users
    try:
        import db
        db.ensure_default_users()
        print("[ARIA] Database connected, default users ready")
        print("[ARIA] Login: admin / AriaAdmin2026!  or  analyst / AriaAnalyst2026!")
    except Exception as _db_err:
        print(f"[ARIA] Database not available ({_db_err}) — running with fallback auth")

    cert = os.path.join(BASE_DIR, 'cert.pem')
    key = os.path.join(BASE_DIR, 'key.pem')
    if os.path.exists(cert) and os.path.exists(key):
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        app.run(host="0.0.0.0", port=443, ssl_context=context)
    else:
        print("[ARIA] No TLS certs found, running on HTTP port 5000")
        app.run(host="0.0.0.0", port=5000)

