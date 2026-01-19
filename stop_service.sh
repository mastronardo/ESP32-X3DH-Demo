#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "--- [System] Stopping the service ---"
docker compose stop