#!/bin/bash
set -e
echo ""
echo "  ARIA Database Setup - RHEL"
echo ""

echo "[1/6] Initializing PostgreSQL..."
sudo postgresql-setup --initdb 2>/dev/null || echo "  Already initialized"

echo "[2/6] Starting PostgreSQL..."
sudo systemctl enable --now postgresql

echo "[3/6] Creating database and user..."
sudo -u postgres psql -c "CREATE USER aria WITH PASSWORD 'AriaDB2026!';" 2>/dev/null || echo "  User already exists"
sudo -u postgres psql -c "CREATE DATABASE ariadb OWNER aria;" 2>/dev/null || echo "  Database already exists"

echo "[4/6] Creating schema..."
sudo -u postgres psql -d ariadb << 'SQL'
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    role VARCHAR(16) DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT NOW()
);
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
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    category VARCHAR(64),
    indicator VARCHAR(256),
    points INTEGER,
    earned INTEGER,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    ioc_type VARCHAR(32),
    value VARCHAR(512),
    context TEXT,
    enriched BOOLEAN DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    format VARCHAR(16) DEFAULT 'pdf',
    data BYTEA,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS user_profiles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE REFERENCES users(id),
    full_name VARCHAR(128),
    email VARCHAR(128) UNIQUE,
    organization VARCHAR(128),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE REFERENCES users(id),
    api_key VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(20) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    customer_name VARCHAR(128) NOT NULL,
    customer_email VARCHAR(128) NOT NULL,
    organization VARCHAR(128),
    total DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'confirmed',
    paypal_order_id VARCHAR(64),
    paypal_status VARCHAR(32),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS order_items (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(20) REFERENCES orders(order_id),
    product_id VARCHAR(32) NOT NULL,
    product_name VARCHAR(128) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    product_type VARCHAR(20)
);
CREATE TABLE IF NOT EXISTS user_services (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    product_id VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    activated_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS user_downloads (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    product_id VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_submitted_at ON scans(submitted_at);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO aria;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO aria;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO aria;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aria;
SQL

echo "[5/6] Configuring remote access..."
grep -q "10.0.1.100" /var/lib/pgsql/data/pg_hba.conf || echo "host ariadb aria 10.0.1.100/32 md5" | sudo tee -a /var/lib/pgsql/data/pg_hba.conf
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '10.0.1.200'/" /var/lib/pgsql/data/postgresql.conf
sudo sed -i "s/listen_addresses = 'localhost'/listen_addresses = '10.0.1.200'/" /var/lib/pgsql/data/postgresql.conf
sudo systemctl restart postgresql

echo "[6/6] Opening firewall..."
sudo firewall-cmd --permanent --add-port=5432/tcp 2>/dev/null || true
sudo firewall-cmd --reload 2>/dev/null || true

echo ""
echo "  Database ready!"
echo "  Host: 10.0.1.200:5432"
echo "  DB: ariadb  User: aria  Pass: AriaDB2026!"
echo ""
