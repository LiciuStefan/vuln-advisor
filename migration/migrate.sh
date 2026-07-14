#!/bin/sh
# Rulează migrările Flyway pentru fiecare bază (database-per-service).
# Se oprește la prima eroare (set -e), astfel încât containerul iese cu cod
# diferit de 0 dacă o migrare eșuează — iar workerii (care depind de finalizarea
# cu succes) nu vor mai porni.
set -e

DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-advisor}"
DB_PASSWORD="${DB_PASSWORD:-advisor}"

run_migration() {
  database="$1"
  location="$2"
  echo "──────────────────────────────────────────────"
  echo "Migrare pentru baza: ${database}"
  flyway \
    -url="jdbc:postgresql://${DB_HOST}:${DB_PORT}/${database}" \
    -user="${DB_USER}" \
    -password="${DB_PASSWORD}" \
    -locations="filesystem:${location}" \
    -connectRetries=10 \
    migrate
}

run_migration advisor_ingestion     /flyway/sql/advisor_ingestion

echo "──────────────────────────────────────────────"
echo "Toate migrările au reușit."
