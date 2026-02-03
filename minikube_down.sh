#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "--- Deleting all Minikube resources..."
minikube delete
rm -rf ~/.minikube/
rm -rf certs/