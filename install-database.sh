#!/bin/bash
# ARIA Database — RHEL Install Script
# Run this on the Database VM (10.0.1.200) as root
# Usage: sudo bash install-database.sh

set -e

echo -e "\n[ARIA DB] Starting PostgreSQL setup...\n"

# 1. Install PostgreSQL
echo "[1/4] Installing PostgreSQL..."
dnf install -y postgresql-server postgresql
postgresql-setup --initdb 2>/dev/null || echo "  Already initialized"
systemctl enable postgresql
systemctl start postgresql

# 2. Create database and user
echo "[2/4] Creating database..."
sudo -u postgres psql -c "CREATE USER aria WITH PASSWORD 'AriaDB2026!';" 2>/dev/null || echo "  User already exists"
sudo -u postgres psql -c "CREATE DATABASE ariadb OWNER aria;" 2>/dev/null || echo "  Database already exists"

# 3. Create schema
echo "[3/4] Creating schema..."
sudo -u postgres psql -d ariadb << 'SQL'
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    role VARCHAR(16) DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    sha256 VARCHAR(64) NOT NULL,
    filename VARCHAR(512) NOT NULL,
    filesize BIGINT,
    mime_type VARCHAR(128),
    verdict VARCHAR(32),
    score INTEGER,
    label VARCHAR(64),
    submitted_by INTEGER REFERENCES users(id),
    submitted_at TIMESTAMP DEFAULT NOW()
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    category VARCHAR(64),
    indicator VARCHAR(256),
    points INTEGER,
    earned INTEGER,
    reason TEXT
);

-- IOCs table
CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    ioc_type VARCHAR(32),
    value VARCHAR(512),
    context TEXT,
    enriched BOOLEAN DEFAULT FALSE
);

-- Reports table (stores generated PDFs)
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    format VARCHAR(16) DEFAULT 'pdf',
    data BYTEA,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_submitted_at ON scans(submitted_at);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO aria;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aria;
SQL

# 4. Allow remote connections from WebServer
echo "[4/4] Configuring remote access..."
PG_HBA=$(find /var/lib/pgsql -name pg_hba.conf 2>/dev/null | head -1)
PG_CONF=$(find /var/lib/pgsql -name postgresql.conf 2>/dev/null | head -1)

if [ -n "$PG_HBA" ]; then
    # Add WebServer access if not already present
    grep -q "10.0.1.100" "$PG_HBA" || echo "host ariadb aria 10.0.1.100/32 md5" >> "$PG_HBA"
    echo "  Updated pg_hba.conf"
fi

if [ -n "$PG_CONF" ]; then
    # Listen on all interfaces
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '10.0.1.200'/" "$PG_CONF"
    sed -i "s/listen_addresses = 'localhost'/listen_addresses = '10.0.1.200'/" "$PG_CONF"
    echo "  Updated postgresql.conf"
fi

# Open firewall
firewall-cmd --permanent --add-port=5432/tcp 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

systemctl restart postgresql

echo -e "\n[ARIA DB] PostgreSQL ready!"
echo "  Database: ariadb"
echo "  User: aria"
echo "  Password: AriaDB2026!"
echo "  Host: 10.0.1.200:5432"
echo "  Accepts connections from: 10.0.1.100 (WebServer)"
echo ""
