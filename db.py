"""
ARIA Database Layer — PostgreSQL integration with security hardening.
All queries use parameterized statements (no string concatenation).
"""
import os
import hashlib
import secrets
import psycopg2
import psycopg2.extras
from functools import wraps
from datetime import datetime, timedelta

DB_HOST = os.environ.get("ARIA_DB_HOST", "10.0.1.200")
DB_PORT = os.environ.get("ARIA_DB_PORT", "5432")
DB_NAME = os.environ.get("ARIA_DB_NAME", "ariadb")
DB_USER = os.environ.get("ARIA_DB_USER", "aria")
DB_PASS = os.environ.get("ARIA_DB_PASS", "AriaDB2026!")

_pool = None

def get_conn():
    """Get a database connection. Creates new if needed."""
    global _pool
    try:
        if _pool and not _pool.closed:
            return _pool
    except Exception:
        pass
    _pool = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS,
        connect_timeout=5
    )
    _pool.autocommit = True
    return _pool

def query(sql, params=None, fetch=True):
    """Execute a parameterized query. Returns rows for SELECT, None for INSERT/UPDATE."""
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params or ())
        if fetch and cur.description:
            return cur.fetchall()
        return None

def query_one(sql, params=None):
    """Execute and return single row."""
    rows = query(sql, params)
    return rows[0] if rows else None


# ══════════════════════════════════════
#  PASSWORD HASHING — PBKDF2 + salt
# ══════════════════════════════════════

def hash_password(password):
    """Hash password with random salt using PBKDF2-SHA256."""
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"

def verify_password(password, stored_hash):
    """Verify password against stored hash."""
    try:
        salt, h = stored_hash.split(':')
        check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return secrets.compare_digest(check.hex(), h)
    except Exception:
        return False


# ══════════════════════════════════════
#  USER MANAGEMENT
# ══════════════════════════════════════

def create_user(username, password, role='analyst'):
    """Create a new user. Returns user dict or None if exists."""
    ph = hash_password(password)
    try:
        query("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
              (username, ph, role), fetch=False)
        return get_user(username)
    except psycopg2.errors.UniqueViolation:
        return None

def get_user(username):
    """Get user by username."""
    return query_one("SELECT id, username, role, created_at FROM users WHERE username = %s", (username,))

def authenticate(username, password):
    """Authenticate user. Returns user dict or None."""
    row = query_one("SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,))
    if row and verify_password(password, row['password_hash']):
        return {'id': row['id'], 'username': row['username'], 'role': row['role']}
    return None

def ensure_default_users():
    """Create default accounts if they don't exist."""
    defaults = [
        ('admin', 'AriaAdmin2026!', 'admin'),
        ('analyst', 'AriaAnalyst2026!', 'analyst'),
    ]
    for user, pw, role in defaults:
        existing = query_one("SELECT id FROM users WHERE username = %s", (user,))
        if not existing:
            create_user(user, pw, role)


# ══════════════════════════════════════
#  SESSION MANAGEMENT
# ══════════════════════════════════════

# In-memory session store (simple, no Redis needed)
_sessions = {}

def create_session(user_id, username, role):
    """Create session token. Returns token string."""
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'created': datetime.utcnow(),
        'expires': datetime.utcnow() + timedelta(hours=8),
    }
    # Clean expired sessions
    now = datetime.utcnow()
    expired = [k for k, v in _sessions.items() if v['expires'] < now]
    for k in expired:
        del _sessions[k]
    return token

def get_session(token):
    """Get session data from token. Returns dict or None."""
    s = _sessions.get(token)
    if s and s['expires'] > datetime.utcnow():
        return s
    if s:
        del _sessions[token]
    return None

def destroy_session(token):
    """Delete session."""
    _sessions.pop(token, None)


# ══════════════════════════════════════
#  SCAN STORAGE
# ══════════════════════════════════════

def save_scan(sha256, filename, filesize, mime_type, verdict, score, label, user_id=None):
    """Save scan result. Returns scan ID."""
    row = query_one(
        "INSERT INTO scans (sha256, filename, filesize, mime_type, verdict, score, label, submitted_by) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (sha256, filename, filesize, mime_type, verdict, score, label, user_id)
    )
    return row['id'] if row else None

def save_findings(scan_id, breakdown):
    """Save scoring breakdown as findings."""
    for item in breakdown:
        query(
            "INSERT INTO findings (scan_id, category, indicator, points, earned, reason) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (scan_id, item.get('label',''), item.get('label',''),
             item.get('points',0), item.get('earned',0), item.get('reason','')),
            fetch=False
        )

def save_iocs(scan_id, iocs):
    """Save extracted IOCs."""
    for ioc in iocs:
        query(
            "INSERT INTO iocs (scan_id, ioc_type, value, context) VALUES (%s, %s, %s, %s)",
            (scan_id, ioc.get('type',''), ioc.get('value',''), ioc.get('context','')),
            fetch=False
        )

def save_report(scan_id, pdf_bytes, fmt='pdf'):
    """Save generated PDF report."""
    query(
        "INSERT INTO reports (scan_id, format, data) VALUES (%s, %s, %s)",
        (scan_id, fmt, psycopg2.Binary(pdf_bytes)),
        fetch=False
    )

def get_scan(scan_id):
    """Get scan by ID."""
    return query_one("SELECT * FROM scans WHERE id = %s", (scan_id,))

def get_scan_by_hash(sha256):
    """Get most recent scan for a given hash."""
    return query_one("SELECT * FROM scans WHERE sha256 = %s ORDER BY submitted_at DESC LIMIT 1", (sha256,))

def get_user_scans(user_id, limit=50):
    """Get recent scans for a user."""
    return query(
        "SELECT id, sha256, filename, filesize, verdict, score, label, submitted_at "
        "FROM scans WHERE submitted_by = %s ORDER BY submitted_at DESC LIMIT %s",
        (user_id, limit)
    )

def get_all_scans(limit=100):
    """Get all recent scans (admin)."""
    return query(
        "SELECT s.id, s.sha256, s.filename, s.filesize, s.verdict, s.score, s.label, "
        "s.submitted_at, u.username FROM scans s LEFT JOIN users u ON s.submitted_by = u.id "
        "ORDER BY s.submitted_at DESC LIMIT %s",
        (limit,)
    )

def get_findings(scan_id):
    """Get findings for a scan."""
    return query("SELECT * FROM findings WHERE scan_id = %s", (scan_id,))

def get_iocs(scan_id):
    """Get IOCs for a scan."""
    return query("SELECT * FROM iocs WHERE scan_id = %s", (scan_id,))

def get_report(scan_id):
    """Get stored PDF report."""
    return query_one("SELECT data, format FROM reports WHERE scan_id = %s ORDER BY created_at DESC LIMIT 1", (scan_id,))

def search_iocs(value):
    """Search IOCs across all scans."""
    return query(
        "SELECT i.*, s.filename, s.sha256 FROM iocs i JOIN scans s ON i.scan_id = s.id "
        "WHERE i.value ILIKE %s LIMIT 50",
        (f"%{value}%",)
    )

def get_scan_count():
    """Get total scan count."""
    row = query_one("SELECT COUNT(*) as cnt FROM scans")
    return row['cnt'] if row else 0

def get_threat_count():
    """Get count of malicious/suspicious scans."""
    row = query_one("SELECT COUNT(*) as cnt FROM scans WHERE verdict IN ('malicious', 'suspicious')")
    return row['cnt'] if row else 0

def get_ioc_count():
    """Get total IOC count."""
    row = query_one("SELECT COUNT(*) as cnt FROM iocs")
    return row['cnt'] if row else 0


# ══════════════════════════════════════
#  E-COMMERCE — Orders
# ══════════════════════════════════════

def ensure_orders_table():
    """Create orders and order_items tables if they don't exist."""
    query("""
        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            order_id VARCHAR(20) UNIQUE NOT NULL,
            customer_name VARCHAR(128) NOT NULL,
            customer_email VARCHAR(128) NOT NULL,
            organization VARCHAR(128),
            total DECIMAL(10,2) NOT NULL,
            status VARCHAR(20) DEFAULT 'confirmed',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """, fetch=False)
    query("""
        CREATE TABLE IF NOT EXISTS order_items (
            id SERIAL PRIMARY KEY,
            order_id VARCHAR(20) REFERENCES orders(order_id),
            product_id VARCHAR(32) NOT NULL,
            product_name VARCHAR(128) NOT NULL,
            price DECIMAL(10,2) NOT NULL
        )
    """, fetch=False)

def create_order(order_id, name, email, org, items, total):
    """Insert a new order and its line items."""
    ensure_orders_table()
    query(
        "INSERT INTO orders (order_id, customer_name, customer_email, organization, total) VALUES (%s,%s,%s,%s,%s)",
        (order_id, name, email, org, total), fetch=False
    )
    for item in items:
        query(
            "INSERT INTO order_items (order_id, product_id, product_name, price) VALUES (%s,%s,%s,%s)",
            (order_id, item['id'], item['name'], item['price']), fetch=False
        )

def get_orders(limit=100):
    """Get all orders, newest first."""
    ensure_orders_table()
    return query("SELECT * FROM orders ORDER BY created_at DESC LIMIT %s", (limit,))

def get_order_items(order_id):
    """Get items for a specific order."""
    return query("SELECT * FROM order_items WHERE order_id = %s", (order_id,))


# ══════════════════════════════════════
#  RATE LIMITING (in-memory)
# ══════════════════════════════════════

_rate_limits = {}

def check_rate_limit(ip, endpoint, max_requests=30, window_seconds=60):
    """Returns True if allowed, False if rate limited."""
    key = f"{ip}:{endpoint}"
    now = datetime.utcnow()
    if key not in _rate_limits:
        _rate_limits[key] = []
    # Clean old entries
    _rate_limits[key] = [t for t in _rate_limits[key] if (now - t).total_seconds() < window_seconds]
    if len(_rate_limits[key]) >= max_requests:
        return False
    _rate_limits[key].append(now)
    return True
