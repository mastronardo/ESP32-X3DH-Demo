#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "--- [Build] Building all containers ---"

docker-compose up -d
echo "--- [System] Waiting for server to be ready..."
while ! curl -s http://localhost:5001/health > /dev/null; do
    echo "Server not up yet. Waiting 2 seconds..."
    sleep 2
done
echo "--- [System] Server is ready! ---"