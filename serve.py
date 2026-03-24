"""
ARIA Production Server — Waitress WSGI
When run by IIS HttpPlatformHandler, uses the port IIS assigns.
When run standalone, defaults to port 5000.
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
    except Exception as e:
        print(f"[ARIA] Database not available ({e}) — running with fallback auth")

    # IIS sets HTTP_PLATFORM_PORT, standalone uses ARIA_PORT or 5000
    port = int(os.environ.get("HTTP_PLATFORM_PORT",
               os.environ.get("ARIA_PORT", "5000")))
    threads = int(os.environ.get("ARIA_THREADS", "8"))

    print(f"[ARIA] Starting on port {port} ({threads} threads)")
    sys.stdout.flush()
    serve(app, host="127.0.0.1", port=port, threads=threads)
