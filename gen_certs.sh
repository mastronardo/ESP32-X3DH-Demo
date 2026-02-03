#!/bin/bash

mkdir -p certs
cd certs

# Generate EC private key
openssl ecparam -name prime256v1 -genkey -noout -out ca.key

# Create Self-Signed CA Certificate
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -nodes \
    -subj "/CN=X3DH-ECC-CA"

# Generate EC private key for Server
openssl ecparam -name prime256v1 -genkey -noout -out server.key

# Create CSR (Certificate Signing Request)
openssl req -new -key server.key -out server.csr -nodes \
    -subj "/CN=rabbitmq"

# Sign the CSR with the CA
openssl x509 -req -in server.csr -out server.crt \
    -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650

# Create the namespace
kubectl create namespace x3dh-project --dry-run=client -o yaml | kubectl apply -f -

# Delete old secret if it exists to avoid conflicts
kubectl delete secret rabbitmq-certs -n x3dh-project --ignore-not-found

# Create new secret with ECC keys
kubectl create secret generic rabbitmq-certs -n x3dh-project \
  --from-file=ca.crt=ca.crt \
  --from-file=tls.crt=server.crt \
  --from-file=tls.key=server.key