#!/usr/bin/env bash
# backup-db.sh — ARIA PostgreSQL backup script for RHEL database server (10.0.1.200)
# Creates timestamped pg_dump backups, rotates old ones, and validates via test restore.

set -euo pipefail

DB_NAME="ariadb"
DB_USER="aria"
DB_PASS="AriaDB2026!"
BACKUP_DIR="/var/backups/aria"
KEEP_COUNT=7
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${TIMESTAMP}.sql.gz"
TEST_DB="${DB_NAME}_restore_test"

export PGPASSWORD="$DB_PASS"

log() { echo "[$(date '+%F %T')] $*"; }

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# --- 1. Create backup ---
log "Starting backup of ${DB_NAME}..."
if pg_dump -U "$DB_USER" -h localhost "$DB_NAME" | gzip > "$BACKUP_FILE"; then
    log "Backup saved: ${BACKUP_FILE} ($(du -h "$BACKUP_FILE" | cut -f1))"
else
    log "FAILURE: pg_dump failed."
    rm -f "$BACKUP_FILE"
    exit 1
fi

# --- 2. Rotate old backups (keep last $KEEP_COUNT) ---
log "Rotating backups (keeping last ${KEEP_COUNT})..."
BACKUPS=($(ls -1t "${BACKUP_DIR}/${DB_NAME}_"*.sql.gz 2>/dev/null))
if [ "${#BACKUPS[@]}" -gt "$KEEP_COUNT" ]; then
    for OLD in "${BACKUPS[@]:$KEEP_COUNT}"; do
        log "  Deleting old backup: $(basename "$OLD")"
        rm -f "$OLD"
    done
fi
log "Backups on disk: $(ls -1 "${BACKUP_DIR}/${DB_NAME}_"*.sql.gz 2>/dev/null | wc -l)"

# --- 3. Test restore ---
log "Testing restore into temporary database '${TEST_DB}'..."
RESTORE_OK=0

# Drop test db if it exists from a previous failed run
dropdb -U "$DB_USER" -h localhost --if-exists "$TEST_DB" 2>/dev/null || true

if createdb -U "$DB_USER" -h localhost "$TEST_DB"; then
    if gunzip -c "$BACKUP_FILE" | psql -U "$DB_USER" -h localhost -q "$TEST_DB" >/dev/null 2>&1; then
        ROW_COUNT=$(psql -U "$DB_USER" -h localhost -t -A -c \
            "SELECT COALESCE(SUM(n_live_tup),0) FROM pg_stat_user_tables;" "$TEST_DB" 2>/dev/null)
        log "  Test restore row count: ${ROW_COUNT}"
        RESTORE_OK=1
    else
        log "  WARNING: psql restore into test db failed."
    fi
    dropdb -U "$DB_USER" -h localhost --if-exists "$TEST_DB" 2>/dev/null || true
else
    log "  WARNING: Could not create test database."
fi

# --- 4. Summary ---
echo ""
echo "======================================"
if [ "$RESTORE_OK" -eq 1 ]; then
    log "SUCCESS: Backup created and restore verified."
else
    log "PARTIAL: Backup created but restore test failed — inspect manually."
fi
echo "======================================"

unset PGPASSWORD

# --- Suggested cron entry (daily at 02:00) ---
# Add to root's crontab with: crontab -e
# 0 2 * * * /home/r4p7ur3/aria-web-deploy/backup-db.sh >> /var/log/aria-backup.log 2>&1
