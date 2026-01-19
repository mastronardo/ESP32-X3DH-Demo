#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "--- [Setup] Cleaning up old runs ---"
docker-compose down
rm -rf server/server-data ./config/