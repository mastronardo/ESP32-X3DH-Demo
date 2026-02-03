# Generate keys.h from WireGuard peer configuration

import sys
import subprocess
from configparser import ConfigParser
from io import StringIO
from os import path

# --- Configuration ---
NAMESPACE = "x3dh-project"
OUTPUT_PATH = "client/main/keys.h"
LOCAL_CA_PATH = "./certs/ca.crt"

def run_kubectl(args):
    """Helper to run kubectl commands and return stdout."""
    cmd = ["kubectl", "-n", NAMESPACE] + args
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.PIPE)
        return result.decode("utf-8").strip()
    except subprocess.CalledProcessError as e:
        print(f"[Error] Kubectl command failed: {' '.join(cmd)}")
        print(e.stderr.decode("utf-8"))
        sys.exit(1)

def get_rabbitmq_ip():
    """Fetches the ClusterIP of the RabbitMQ service."""
    print(" -> Fetching RabbitMQ Service IP...")
    ip = run_kubectl(["get", "svc", "rabbitmq-client", "-o", "jsonpath={.spec.clusterIP}"])
    return ip

def get_wireguard_pod():
    """Finds the name of the running WireGuard pod."""
    print(" -> Finding WireGuard Pod...")
    pod_name = run_kubectl(["get", "pods", "-l", "app=wireguard", "-o", "jsonpath={.items[0].metadata.name}"])
    return pod_name

def get_peer_config(pod_name, peer_num):
    """Reads peer config content directly from the pod."""
    peer_id = f"peer{peer_num}"
    config_path = f"/config/{peer_id}/{peer_id}.conf"
    print(f" -> Reading {config_path} from pod {pod_name}...")
    content = run_kubectl(["exec", pod_name, "--", "cat", config_path])
    return content

def format_pem_for_c(pem_content):
    """Formats a PEM string into a C-compatible multi-line string."""
    lines = pem_content.strip().splitlines()
    c_lines = [f'    "{line}\\n" ' + '\\' for line in lines]
    # Remove the backslash from the last line
    if c_lines:
        c_lines[-1] = c_lines[-1].rstrip(' \\')
    return "\n".join(c_lines)

def generate_header(host_ip, peer_num):
    # Get Dynamic Info from K8s
    rabbitmq_ip = get_rabbitmq_ip()
    
    # Check if IP retrieval worked
    if not rabbitmq_ip or rabbitmq_ip == "None":
        print("[Error] Could not get RabbitMQ IP. Ensure 'rabbitmq-client' service exists.")
        sys.exit(1)

    wg_pod = get_wireguard_pod()
    config_content = get_peer_config(wg_pod, peer_num)

    # Parse WireGuard Config
    config = ConfigParser()
    config.read_file(StringIO(config_content))

    try:
        priv_key = config['Interface']['PrivateKey']
        address = config['Interface']['Address'].split('/')[0]
        server_pub = config['Peer']['PublicKey']
    except KeyError as e:
        print(f"[Error] Failed to parse config from pod: Missing {e}")
        sys.exit(1)

    # Read Local CA Cert
    if not path.exists(LOCAL_CA_PATH):
        print(f"[Error] CA Cert not found at {LOCAL_CA_PATH}. Did you run gen_certs_ecc.sh?")
        sys.exit(1)
    
    with open(LOCAL_CA_PATH, 'r') as f:
        ca_pem = f.read()
    
    ca_c_string = format_pem_for_c(ca_pem)

    # Generate C Header
    header_content = f"""#ifndef KEYS_H
#define KEYS_H

// --- Identity for Peer {peer_num} ---
#define WG_PRIVATE_KEY      "{priv_key}"
#define WG_LOCAL_IP_ADDR    "{address}"
#define WG_LOCAL_IP_NETMASK "255.0.0.0"

// --- WireGuard Server ---
#define WG_SERVER_PUB_KEY   "{server_pub}"
#define WG_ENDPOINT_IP      "{host_ip}"
#define WG_ENDPOINT_PORT    30000

// --- MQTT Configuration ---
#define MQTT_BROKER_URI     "mqtts://{rabbitmq_ip}:8883" 

// --- Security ---
#define MQTT_CA_CERT_PEM \\
{ca_c_string}

#endif // KEYS_H
"""

    with open(OUTPUT_PATH, "w") as f:
        f.write(header_content)
    
    print(f"\n[Success] Generated {OUTPUT_PATH}")
    print(f"  WireGuard IP: {address}")
    print(f"  Broker URI:   mqtts://{rabbitmq_ip}:8883")
    print(f"  Endpoint:     {host_ip}:30000")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 generate_keys.py <YOUR_HOST_IP> <PEER_NUMBER>")
        sys.exit(1)
    generate_header(sys.argv[1], sys.argv[2])