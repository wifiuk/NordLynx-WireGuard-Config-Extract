#!/bin/bash
echo "NordVPN needs to be installed and your credentials added for this to work."
echo "If you have not already installed wireguard, please do so before running this tool."
echo "sudo apt install wireguard -y"
echo "usage example: sudo bash NordLynxExtractKeys.sh uk"
echo ""
echo ""
echo "== Setting NordVPN to use NordLynx =="
nordvpn set technology NordLynx > /dev/null 2>&1
echo "== Connecting to NordVPN Server =="
nordvpn c $1 > /dev/null 2>&1
echo "== Now extracting Wireguard Configurtion infomation =="
current_server=$(nordvpn status | grep "Current server:" |awk '{print $3 "\t" $4}')
public_key=$(sudo wg show | grep "public key")
listening_port=$(sudo wg showconf nordlynx | grep "ListenPort")
private_key=$(sudo wg showconf nordlynx | grep "PrivateKey")
allowed_ip=$(sudo wg showconf nordlynx | grep "AllowedIPs")
endpoint=$(sudo wg showconf nordlynx | grep "Endpoint")
keepalive=$(sudo wg showconf nordlynx | grep "PersistentKeepalive")
echo "== Saving information to file $current_server =="
echo ""
echo ""
echo "Server Name = $current_server " | tee $current_server
echo "[Interface]" | tee -a $current_server
echo ""
echo $listening_port | tee -a $current_server
echo ""
echo $private_key | tee -a $current_server
echo ""
echo ""
echo ""
echo "[Peer]" | tee -a $current_server
echo ""
echo $public_key | tee -a $current_server
echo ""
echo $allowed_ip | tee -a $current_server
echo ""
echo $endpoint | tee -a $current_server
echo ""
echo $keepalive | tee -a $current_server

echo ""
echo ""
echo "== Disconnecting from NordVPN =="
sudo nordvpn d > /dev/null 2>&1
