# Generate keys.h from WireGuard peer configuration

from configparser import ConfigParser
from os import path
import sys

WG_CONFIG_DIR = './config/wireguard'
OUTPUT_HEADER_PATH = 'client/main/keys.h'

def generate_header(host_ip, peer_num):
    peer_id = f"peer{peer_num}"
    conf_path = path.join(WG_CONFIG_DIR, peer_id, f"{peer_id}.conf")
    
    if not path.exists(conf_path):
        print(f"[Error] Config not found: {conf_path}")
        print(f"Did you set PEERS={peer_num} (or higher) in docker-compose.yml?")
        sys.exit(1)

    print(f"Reading configuration for {peer_id}...")
    config = ConfigParser()
    config.read(conf_path)

    try:
        # Extract Keys
        private_key = config['Interface']['PrivateKey']
        address_block = config['Interface']['Address']
        client_ip = address_block.split('/')[0]
        public_key = config['Peer']['PublicKey']

        c_content = f"""#ifndef KEYS_H
#define KEYS_H

// --- Identity for {peer_id} ---
#define WG_PRIVATE_KEY      "{private_key}"
#define WG_LOCAL_IP_ADDR    "{client_ip}"
#define WG_LOCAL_IP_NETMASK "255.255.255.255"

// --- Server Identity ---
#define WG_SERVER_PUB_KEY   "{public_key}"
#define WG_ENDPOINT_IP      "{host_ip}"
#define WG_ENDPOINT_PORT    51820

#endif // KEYS_H
"""
        with open(OUTPUT_HEADER_PATH, 'w') as f:
            f.write(c_content)
        print(f"\n[Success] Generated {OUTPUT_HEADER_PATH} for {peer_id}")
        print(f" -> IP: {client_ip}")

    except KeyError as e:
        print(f"\n[Error] Key not found: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 generate_keys.py <YOUR_PC_IP> <PEER_NUMBER>")
        print("Example: python3 generate_keys.py 192.168.1.50 1")
        sys.exit(1)
    
    generate_header(sys.argv[1], sys.argv[2])