"""
ARIA Production Server — Waitress WSGI
Run this instead of 'python api.py' for production.
"""
from waitress import serve
from api import app
import os
import sys

if __name__ == "__main__":
    # Initialize database
    try:
        import db
        db.ensure_default_users()
        print("[ARIA] Database connected, default users ready")
        print("[ARIA] Login: admin / AriaAdmin2026!  or  analyst / AriaAnalyst2026!")
    except Exception as e:
        print(f"[ARIA] Database not available ({e}) — running with fallback auth")

    host = "0.0.0.0"
    port = int(os.environ.get("ARIA_PORT", "5000"))
    threads = int(os.environ.get("ARIA_THREADS", "8"))

    print(f"[ARIA] Production server starting on {host}:{port} ({threads} threads)")
    print(f"[ARIA] IIS should reverse proxy to http://127.0.0.1:{port}")
    serve(app, host=host, port=port, threads=threads)
