#!/bin/bash

CONFIG_FILE="/config/wg_confs/wg0.conf"
FLAG_FILE="/config/wg_confs/.wg_config_updated"

# Check if the flag file exists. If it does, exit immediately.
if [ -f "$FLAG_FILE" ]; then
    echo "Config already updated. Skipping script."
    exit 0
fi

echo "First run detected. Updating WireGuard config..."

# Comment out PresharedKeys
if [ -f "$CONFIG_FILE" ]; then
    # Backup
    cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    
    # Comment PSK
    sed -i '/^[[:space:]]*#/!s/^[[:space:]]*PresharedKey/# &/' "$CONFIG_FILE"
    
    # Define New Rules
    NEW_POSTUP="PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth+ -j MASQUERADE; iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
    NEW_POSTDOWN="PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth+ -j MASQUERADE; iptables -t mangle -D FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"

    # Replace PostUp/PostDown
    sed -i "s|^PostUp[[:space:]]*=.*|$NEW_POSTUP|" "$CONFIG_FILE"
    sed -i "s|^PostDown[[:space:]]*=.*|$NEW_POSTDOWN|" "$CONFIG_FILE"
    
    echo "WireGuard config updated successfully."
else
    echo "Config file not found at $CONFIG_FILE"
fi

# Create the flag file so this doesn't run again
touch "$FLAG_FILE"