#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo -e "--- Starting Minikube...\n"

echo "Which container runtime would you like to use?"
PS3='Please enter your choice (number): '
options=("Docker" "Containerd" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Docker")
            echo "-------------------------------------"
            minikube start --driver=docker --container-runtime=docker --ports=30000:30000/udp,30080:30080/tcp
            break
            ;;
        "Containerd")
            echo "-------------------------------------"
            minikube start --driver=docker --container-runtime=containerd --ports=30000:30000/udp,30080:30080/tcp
            break
            ;;
        "Quit")
            echo "Exiting..."
            exit 0
            ;;
        *) 
            echo "Invalid option. Please choose a valid number."
            ;;
    esac
done

minikube addons enable metrics-server
minikube addons enable headlamp
minikube image load x3dh-server:1.1
echo -e "--- Minikube is ready!\n"

echo "--- Generating Certificates and Namespace..."
./gen_certs.sh
sleep 1
echo -e "--- Certificates and Namespace 'x3dh-project' generated!\n"

echo "--- Applying CloudNativePG Operator..."
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.28/releases/cnpg-1.28.0.yaml
sleep 55
echo -e "--- CloudNativePG Operator applied!\n"

echo "--- Applying Kubernetes deployments..."
kubectl apply -f k8s-deployment.yaml
kubectl apply -f postgres-cluster.yaml
kubectl apply -f pgadmin.yaml
echo -e "--- Kubernetes deployments applied!\n"