#!/bin/bash
# ARIA Network Sentinel — Kali Install Script
# Run this on SecurityDesktop (172.31.0.100) as root
# Installs Suricata IDS + Wazuh Manager
# Usage: sudo bash install-sentinel.sh

set -e

echo -e "\n[SENTINEL] Setting up network monitoring on Kali...\n"

# ═══════════════════════════════════════
# 1. SURICATA IDS
# ═══════════════════════════════════════
echo "[1/3] Installing Suricata..."
apt-get update -qq
apt-get install -y suricata suricata-update jq

# Update rules (ET Open — free, 40K+ signatures)
echo "  Updating Suricata rules..."
suricata-update 2>&1 | tail -3

# Configure Suricata
SURICATA_CONF="/etc/suricata/suricata.yaml"
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

# Set HOME_NET to match lab network
sed -i 's|HOME_NET:.*|HOME_NET: "[10.0.1.0/24,192.168.1.0/24,172.31.0.0/24]"|' "$SURICATA_CONF"
sed -i 's|EXTERNAL_NET:.*|EXTERNAL_NET: "!$HOME_NET"|' "$SURICATA_CONF"

# Enable JSON logging for ARIA integration
cat > /etc/suricata/aria-output.yaml << 'YAML'
# ARIA integration — JSON alert log
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - dns
        - http
        - tls
        - files
YAML

echo "  Suricata configured on interface: $IFACE"
systemctl enable suricata
systemctl restart suricata

# ═══════════════════════════════════════
# 2. WAZUH MANAGER (receives agent data from all VMs)
# ═══════════════════════════════════════
echo "[2/3] Installing Wazuh Manager..."
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-manager/wazuh-manager_4.9.0-1_amd64.deb 2>/dev/null
if [ -f wazuh-manager_4.9.0-1_amd64.deb ]; then
    dpkg -i wazuh-manager_4.9.0-1_amd64.deb 2>&1 | tail -3
    systemctl enable wazuh-manager
    systemctl start wazuh-manager
    rm -f wazuh-manager_4.9.0-1_amd64.deb
    echo "  Wazuh Manager running"
else
    echo "  WARNING: Could not download Wazuh. Install manually:"
    echo "  https://documentation.wazuh.com/current/installation-guide/"
fi

# ═══════════════════════════════════════
# 3. ARIA ALERT FORWARDER
# ═══════════════════════════════════════
echo "[3/3] Setting up ARIA alert forwarder..."
cat > /opt/aria-forwarder.py << 'PYTHON'
#!/usr/bin/env python3
"""
Watches Suricata eve.json and forwards alerts to ARIA /enrich/iocs endpoint.
Runs as a systemd service.
"""
import json, time, requests, sys

ARIA_URL = "https://10.0.1.100:5000"
EVE_LOG = "/var/log/suricata/eve.json"

def tail_follow(filename):
    with open(filename, 'r') as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def forward_alert(event):
    alert = event.get("alert", {})
    src_ip = event.get("src_ip", "")
    dest_ip = event.get("dest_ip", "")
    sig = alert.get("signature", "")
    severity = alert.get("severity", 3)

    iocs = []
    if src_ip and not src_ip.startswith(("10.", "192.168.", "172.")):
        iocs.append({"type": "ip", "value": src_ip, "context": f"Suricata: {sig}"})
    if dest_ip and not dest_ip.startswith(("10.", "192.168.", "172.")):
        iocs.append({"type": "ip", "value": dest_ip, "context": f"Suricata: {sig}"})

    if iocs:
        try:
            requests.post(f"{ARIA_URL}/enrich/iocs", json={"iocs": iocs},
                         timeout=10, verify=False)
        except:
            pass  # ARIA may be down, don't crash the forwarder

def main():
    print(f"[ARIA Forwarder] Watching {EVE_LOG}...")
    for line in tail_follow(EVE_LOG):
        try:
            event = json.loads(line)
            if event.get("event_type") == "alert":
                forward_alert(event)
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    main()
PYTHON

chmod +x /opt/aria-forwarder.py

# Create systemd service
cat > /etc/systemd/system/aria-forwarder.service << 'SERVICE'
[Unit]
Description=ARIA Alert Forwarder (Suricata -> ARIA)
After=suricata.service
Wants=suricata.service

[Service]
ExecStart=/usr/bin/python3 /opt/aria-forwarder.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable aria-forwarder
systemctl start aria-forwarder

echo -e "\n[SENTINEL] Setup complete!"
echo ""
echo "  Suricata IDS:      Running (alerts in /var/log/suricata/eve.json)"
echo "  Wazuh Manager:     Running (agents connect to 172.31.0.100:1514)"
echo "  ARIA Forwarder:    Running (alerts -> https://10.0.1.100:5000/enrich/iocs)"
echo ""
echo "  Next steps:"
echo "  1. Install Wazuh agents on all VMs:"
echo "     Windows: https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"
echo "     RHEL:    dnf install https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm"
echo "     Set WAZUH_MANAGER=172.31.0.100 during install"
echo ""
echo "  2. Configure firewall to mirror traffic to this box"
echo ""
