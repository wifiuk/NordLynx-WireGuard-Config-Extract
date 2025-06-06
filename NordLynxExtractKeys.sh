#!/bin/bash
echo -e "\nCode is from : https://github.com/wifiuk/NordLynx-WireGuard-Config-Extract\n\n"
echo "NordVPN needs to be installed and your credentials added for this to work."
echo "If you have not already installed wireguard, please do so before running this tool."
echo "sudo apt install wireguard -y"
echo ""
echo ""
# Check to make sure you have the right privileges
if [[ $(id -u) -ne 0 ]]; then
    echo "ERROR: Incorrect usage."
    echo "usage example: sudo bash $(basename $0) uk"
    exit -1
fi

# location to write files to.
file_save_dir="."
# flag to indicate that we 'force' connected to nordvpn.
flag_system_triggered_connection=0 
# Check if 'nordvpnd' daemon is running
pid_nordvpn=$(pgrep -u root nordvpnd)
if [[ $? -eq 0 ]]; then
    # If it's running...check it's status.
    status_=$(nordvpn status | awk '/Status:\s+.*/ {print $NF}')
    if [[ "$status_" == "Connected" ]]; then
        # if it's connected to a vpn just show that info.
        flag_system_triggered_connection=0
        echo "== NordVPN is Already Running =="

    elif [[ "$status_" == "Disconnected" ]]; then
        # if it's not connected to a vpn first connect then show info.
        flag_system_triggered_connection=1

        echo "== NordVPN is Disconnected =="

        echo "== Setting NordVPN to use NordLynx =="
        nordvpn set technology NordLynx > /dev/null 2>&1

        echo "== Connecting to NordVPN Server =="
        nordvpn c $1 > /dev/null 2>&1
    fi

else
    echo "============================================="
    echo "ERROR: NordVPN Daemon is Not Running"
    echo "run: 'sudo systemctl restart nordvpnd'"
    echo "============================================="
    exit -1
fi


echo "== Now extracting Wireguard Configurtion infomation =="

nordvpn_status=$(nordvpn status)
current_server_name=$(cat <<< "$nordvpn_status" | grep -i server | sed 's/Server:\s\+//' | tr ' ' '_')
current_server_city=$(cat <<< "$nordvpn_status" | grep -i city | sed 's/City:\s\+//' | tr ' ' '_')
current_server_country=$(cat <<< "$nordvpn_status" | grep -i country | sed 's/Country:\s\+//' | tr ' ' '_')
current_server=$(awk '/Hostname:/ {print $NF}' <<< "$nordvpn_status")

wireguard_status=$(sudo wg show)
public_key=$(awk '/public key:/ {print $NF}' <<< "$wireguard_status")

inet=$(ip addr show dev nordlynx | awk '/inet/ {print $2}')

wg_conf=$(sudo wg showconf nordlynx)
listening_port=$(awk '/ListenPort/ {print $NF}' <<< "$wg_conf")
private_key=$(awk '/PrivateKey/ {print $NF}' <<< "$wg_conf")
allowed_ip=$(awk '/AllowedIPs/ {print $NF}' <<< "$wg_conf")
endpoint=$(awk '/Endpoint/ {print $NF}' <<< "$wg_conf")
keepalive=$(awk '/PersistentKeepalive/ {print $NF}' <<< "$wg_conf")

# a copy of the output is sent here.
save_file="${file_save_dir}/${current_server}.txt"
cat << EOF | tee "$save_file"
Server Hostname = ${current_server}
Server Name = ${current_server_name}
Server City = ${current_server_city}
Server Country = ${current_server_country}

[Interface]
ListenPort: ${listening_port}
PrivateKey: ${private_key}

[Peer]
PublicKey: ${public_key}
AllowedIPs: ${allowed_ip}
Endpoint: ${endpoint}
keepalive: ${keepalive}

[Address]
inet: ${inet}
EOF

echo ""
echo ""
echo "== File saved : $save_file =="


if [[ "$flag_system_triggered_connection" == "1" ]]; then
    echo "== Disconnecting from NordVPN =="
    sudo nordvpn d > /dev/null 2>&1
fi
