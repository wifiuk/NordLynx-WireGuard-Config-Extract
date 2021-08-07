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
interface=$(sudo wg show | grep "interface")
public_key=$(sudo wg show | grep "public key")
listening_port=$(sudo wg show | grep "listening port")
peer=$(sudo wg show | grep "peer")
endpoint=$(sudo wg show | grep "endpoint")
keepalive=$(sudo wg show | grep "persistent keepalive")
echo "== Saving information to file $current_server =="
echo ""
echo ""
echo $current_server | tee $current_server
echo $interface | tee -a $current_server
echo $public_key | tee -a $current_server
echo $listening_port | tee -a $current_server
echo $peer | tee -a $current_server
echo $endpoint | tee -a $current_server
echo $keepalive | tee -a $current_server
echo ""
echo""
echo "== Disconnecting from NordVPN =="
sudo nordvpn d > /dev/null 2>&1
