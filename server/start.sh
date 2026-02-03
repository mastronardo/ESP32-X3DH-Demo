#!/bin/bash
set -e

# Default values to match server.py if env variables aren't set
: "${DB_HOST:=insert-your-db-host-here}"
: "${DB_USER:=insert-your-db-user-here}"

# Wait for Postgres
echo "Checking connection to $DB_HOST..."
until pg_isready -h "$DB_HOST" -p 5432 -U "$DB_USER"; do
  echo -e "Postgres is unavailable - sleeping 10s...\n"
  sleep 10
done
echo -e "Postgres is ready!\n"

# Activate venv and start Python Server
. /app/venv-mqtt/bin/activate
exec python3 /app/server.py