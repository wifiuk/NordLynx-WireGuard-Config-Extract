#!/bin/bash

# =============================================
# USER CONFIGURATION SECTION
# =============================================

# Maximum attempts to find a clean NordVPN exit IP before giving up
max_attempts=10
# ------------------------------
# Colour codes
RED='\033[0;31m'; GREEN='\033[0;32m'; LIGHT_GREEN='\033[1;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; LIGHT_CYAN='\033[1;36m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'

command_exists(){ command -v "$1" >/dev/null 2>&1; }
error_msg(){   printf "${RED}%b${NC}\n" "$1"; }
success_msg(){ printf "${GREEN}%b${NC}\n" "$1"; }
info_msg(){    printf "${BLUE}%b${NC}\n" "$1"; }
warning_msg(){ printf "${YELLOW}%b${NC}\n" "$1"; }

# Live HTTPS blocklist checks: 0 = no listing, 1 = listed, 2 = unknown.
# Query positive and negative controls so blocked resolvers cannot look clean.
dnsbl_lookup(){
    local query="$1" reply status
    if [[ "$query" == *.bl.spamcop.net ]]; then
        reply=$(curl --fail --silent --show-error --connect-timeout 5 --max-time 10 \
            --get --data-urlencode "name=$query" --data-urlencode 'type=A' \
            https://dns.google/resolve 2>/dev/null) || return 2
        printf '%s' "$reply" | python3 -c '
import json, sys
try:
    response = json.load(sys.stdin)
    status = response["Status"]
    answers = [a["data"] for a in response.get("Answer", []) if a.get("type") == 1]
    result = 0 if status == 3 else (1 if status == 0 and "127.0.0.2" in answers else 2)
except (ValueError, KeyError, TypeError):
    result = 2
sys.exit(result)
'
        return $?
    fi
    return 2
}

dnsbl_check(){
    local ip="$1" zone="$2" result a b c d
    dnsbl_lookup "2.0.0.127.$zone"; result=$?
    [[ $result == 1 ]] || { echo 'Unknown (resolver failed listed control)'; return 2; }
    dnsbl_lookup "1.0.0.127.$zone"; result=$?
    [[ $result == 0 ]] || { echo 'Unknown (resolver failed unlisted control)'; return 2; }
    IFS=. read -r a b c d <<< "$ip"
    dnsbl_lookup "$d.$c.$b.$a.$zone"; result=$?
    case $result in
        0) echo 'Not listed in this blocklist' ;;
        1) echo 'Listed in this blocklist' ;;
        2) echo 'Unknown (DNS error or refused lookup)' ;;
    esac
    return "$result"
}

# Fetch each HTTPS feed once per script run; reuse it across VPN retries.
# Spamhaus DROP is a network abuse list, distinct from Spamhaus ZEN.
load_online_feeds(){
    [[ "${feeds_loaded:-0}" == 1 ]] && return
    drop_feed=$(curl --fail --silent --show-error --location --connect-timeout 5 --max-time 20 \
        https://www.spamhaus.org/drop/drop_v4.json 2>/dev/null) || drop_feed=''
    et_feed=$(curl --fail --silent --show-error --location --connect-timeout 5 --max-time 20 \
        https://rules.emergingthreats.net/blockrules/compromised-ips.txt 2>/dev/null) || et_feed=''
    feeds_loaded=1
}

feed_check(){
    local ip="$1" format="$2" data="$3"
    printf '%s' "$data" | python3 -c '
import ipaddress, json, sys
try:
    ip = ipaddress.IPv4Address(sys.argv[1])
    networks = []
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if sys.argv[2] == "json":
            item = json.loads(line)
            if "cidr" not in item:
                if "timestamp" in item and "copyright" in item:
                    continue
                raise ValueError("Unexpected feed record")
            line = item["cidr"]
        networks.append(ipaddress.IPv4Network(line, strict=True))
    if not networks:
        raise ValueError("Empty feed")
    matches = [str(n) for n in networks if ip in n]
    if matches:
        print("Listed: " + ", ".join(matches))
        sys.exit(1)
    print("Not listed (checked %d entries)" % len(networks))
except (ValueError, KeyError, TypeError):
    print("Unknown (download failed or invalid feed)")
    sys.exit(2)
' "$ip" "$format"
}

check_ip_blacklists(){
    local ip="${1:-}" endpoint octet
    if [[ -z "$ip" ]]; then
        for endpoint in https://api.ipify.org https://icanhazip.com; do
            ip=$(curl -4 --fail --silent --show-error --connect-timeout 5 --max-time 10 "$endpoint" 2>/dev/null) || { ip=''; continue; }
            [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && break
            ip=''
        done
    fi
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { warning_msg 'Could not determine a valid public IPv4 address'; return 2; }
    local -a octets
    IFS=. read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || { warning_msg 'Invalid IPv4 address'; return 2; }
    done
    printf '\nPublic IPv4: %s\n' "$ip"
    load_online_feeds
    local result listed=0 unknown=0
    printf '%-25s | ' 'SpamCop (HTTPS)'
    dnsbl_check "$ip" bl.spamcop.net; result=$?
    [[ $result == 1 ]] && listed=1
    [[ $result == 2 ]] && unknown=1
    printf '%-25s | ' 'Spamhaus DROP (HTTPS)'
    feed_check "$ip" json "$drop_feed"; result=$?
    [[ $result == 1 ]] && listed=1
    [[ $result == 2 ]] && unknown=1
    printf '%-25s | ' 'ET compromised IPs (HTTPS)'
    feed_check "$ip" text "$et_feed"; result=$?
    [[ $result == 1 ]] && listed=1
    [[ $result == 2 ]] && unknown=1
    (( listed )) && return 1
    (( unknown )) && return 2
    return 0
}

# Read-only lookup mode; does not run VPN setup or extract keys.
if [[ "${1:-}" == '--check-ip' ]]; then
    command_exists curl && command_exists python3 || { error_msg 'curl and python3 are required'; exit 2; }
    check_ip_blacklists "${2:-}"
    exit $?
fi

# ----- Connect until a clean IP is found -----
nord_connect_until_clean(){
    local target="$1"
    local attempt=1
    
    while (( attempt <= max_attempts )); do
        info_msg "Connecting to NordVPN ($target) — attempt $attempt/$max_attempts..."
        
        # Disconnect first to ensure clean state
        sudo nordvpn d &>/dev/null
        sleep 2
        
        local output
        output=$(sudo nordvpn c "$target" 2>&1)
        
        if [[ $? -ne 0 ]]; then
            error_msg "NordVPN connect failed: $output"
            if [[ "$output" == *"not logged in"* ]]; then
                error_msg "Please log in to NordVPN first: sudo nordvpn login"
                exit 1
            fi
            ((attempt++))
            continue
        fi
        
        # Extract server name more reliably
        server_name=$(echo "$output" | grep -oP 'Connected to \K[^.]+' | head -n1)
        [[ -z "$server_name" ]] && server_name=$(echo "$output" | grep -oP '\(\K[^)]+' | head -n1)
        [[ -z "$server_name" ]] && server_name="Unknown Server"
        
        success_msg "Connected to $server_name"
        
        # Set MTU for better performance
        sudo ip link set dev nordlynx mtu 1350 2>/dev/null
        
        # Wait a moment for connection to stabilize
        sleep 3
        
        check_ip_blacklists
        local lookup_result=$?
        if [[ $lookup_result -eq 0 ]]; then
            success_msg "Exit IP is not listed in any of the three checked blocklists."
            return 0
        elif [[ $lookup_result -eq 2 ]]; then
            warning_msg "Reputation checks are inconclusive. Stopping without retrying or claiming this IP is clean."
            return 2
        else
            warning_msg "Exit IP blacklisted — disconnecting & retrying..."
            sudo nordvpn d &>/dev/null
            ((attempt++))
            sleep 2
        fi
    done
    
    error_msg "Failed to get a clean exit IP after $max_attempts attempts."
    exit 2
}

# ----- Start of script -----
clear
printf "${PURPLE}==============================================${NC}\n"
printf "${PURPLE}   NordVPN WireGuard Configuration Script     ${NC}\n"
printf "${PURPLE}==============================================${NC}\n\n"

# Software checks
info_msg "Checking for required software..."
for tool in nordvpn wg curl python3; do
    if ! command_exists "$tool"; then
        error_msg "$tool is not installed. Please install it."
        case "$tool" in
            nordvpn) error_msg "Install from: https://nordvpn.com/download/linux/" ;;
            wg) error_msg "Install: sudo apt install wireguard-tools" ;;
            curl) error_msg "Install: sudo apt install curl" ;;
            dig) error_msg "Install: sudo apt install dnsutils" ;;
        esac
        exit 1
    fi
done
success_msg "All required software is installed."
printf "\n"

# NordLynx self-healing
sudo -v || { error_msg "Need sudo privileges."; exit 1; }
info_msg "Enabling NordLynx…"
sudo nordvpn set technology nordlynx &>/dev/null

for i in {1..5}; do
    tech=$(nordvpn settings 2>/dev/null | awk -F': ' '/Technology/{print tolower($2)}' | tr -d '[:space:]')
    [[ "$tech" == "nordlynx" ]] && break
    sleep 1
done

[[ "$tech" == "nordlynx" ]] || {
    error_msg "Could not enable NordLynx.
• Are you logged in? → sudo nordvpn login
• Restart daemon?   → sudo systemctl restart nordvpnd
• WireGuard kernel? → sudo apt install wireguard wireguard-tools"
    exit 1
}
success_msg "NordLynx is active."
printf "\n"

# Menu prompt
printf "${CYAN}Please choose an option:${NC}\n"
printf "1. Edit an existing WireGuard connection\n"
printf "2. Create a new WireGuard connection\n\n"

while read -rp "$(printf "${YELLOW}Enter 1 or 2: ${NC}")" choice; do
    [[ "$choice" =~ ^[12]$ ]] && break
    warning_msg "Invalid choice; enter 1 or 2."
done
printf "\n"

# Edit existing
edit_existing_connection(){
    info_msg "Editing an existing WireGuard connection..."
    read -rp "$(printf "${YELLOW}Enter the country code or server (e.g., 'uk' or 'uk1740'): ${NC}")" vpn_target
    
    nord_connect_until_clean "$vpn_target" || exit $?
    
    info_msg "Extracting WireGuard configuration..."
    local wg_conf listening_port endpoint endpoint_ip
    wg_conf=$(sudo wg showconf nordlynx 2>/dev/null)
    
    if [[ -z "$wg_conf" ]]; then
        error_msg "Failed to extract WireGuard config - interface may not be active"
        sudo nordvpn d
        exit 1
    fi
    
    listening_port=$(echo "$wg_conf" | grep 'ListenPort' | awk '{print $3}')
    endpoint=$(echo "$wg_conf" | grep 'Endpoint'   | awk '{print $3}')
    endpoint_ip=${endpoint%%:*}
    
    [[ -z "$listening_port" || -z "$endpoint_ip" ]] && {
        error_msg "Failed to extract WireGuard config."
        sudo nordvpn d
        exit 1
    }
    
    info_msg "Disconnecting from NordVPN..."
    sudo nordvpn d >/dev/null
    
    # Original interactive guide
    printf "\n${GREEN}==================================================================${NC}\n"
    printf "${GREEN}Please update your pfSense configuration with the following values:${NC}\n"
    printf "${GREEN}==================================================================${NC}\n\n"
    printf "${YELLOW}%-25b %-45b${NC}\n" "Configuration" "Value"
    printf "${YELLOW}%-25b %-45b${NC}\n" "-------------" "-----"
    printf "${BLUE}%-25b${NC}\n" "1. Tunnel Configuration (e.g TUN_wg2):"
    printf "${LIGHT_CYAN}%-25b${NC} %-45b\n" "Listening Port:" "${LIGHT_GREEN}$listening_port${NC}"
    printf "\n"
    printf "${BLUE}%-25b${NC}\n" "2. Peer Configuration:"
    printf "${LIGHT_CYAN}%-25b${NC} %-45b\n" "Description:" "${LIGHT_GREEN}$server_name${NC}"
    printf "${LIGHT_CYAN}%-25b${NC} %-45b\n" "Endpoint:" "${LIGHT_GREEN}$server_name${NC}"
    printf "\n"
    printf "${BLUE}%-25b${NC}\n" "3. Routing:"
    printf "${LIGHT_CYAN}%-25b${NC} %-45b\n" "Destination network:" "${LIGHT_GREEN}$endpoint_ip/32${NC}"
    printf "${LIGHT_CYAN}%-25b${NC} %-45b\n" "Gateway:" "WAN PPOE"
    printf "${LIGHT_CYAN}%-25b${NC} %-45b\n" "Description:" "${LIGHT_GREEN}$server_name${NC}"
    printf "\n"
    printf "${GREEN}==================================================================${NC}\n"
    printf "\n"
}

# Create new
create_new_connection(){
    info_msg "Creating a new WireGuard connection..."
    read -rp "$(printf "${YELLOW}Enter the country code or server (e.g., 'uk' or 'uk1740'): ${NC}")" vpn_target
    
    nord_connect_until_clean "$vpn_target" || exit $?
    
    info_msg "Extracting WireGuard configuration..."
    local wg_conf private_key listening_port endpoint endpoint_ip public_key
    wg_conf=$(sudo wg showconf nordlynx 2>/dev/null)
    
    if [[ -z "$wg_conf" ]]; then
        error_msg "Failed to extract WireGuard config - interface may not be active"
        sudo nordvpn d
        exit 1
    fi
    
    private_key=$(echo "$wg_conf" | grep 'PrivateKey' | awk '{print $3}')
    listening_port=$(echo "$wg_conf" | grep 'ListenPort' | awk '{print $3}')
    endpoint=$(echo "$wg_conf" | grep 'Endpoint' | awk '{print $3}')
    endpoint_ip=${endpoint%%:*}
    public_key=$(echo "$wg_conf" | grep 'PublicKey' | awk '{print $3}')
    
    [[ -z "$private_key" || -z "$listening_port" || -z "$endpoint_ip" || -z "$public_key" ]] && {
        error_msg "Failed to extract WireGuard config."
        sudo nordvpn d
        exit 1
    }
    
    info_msg "Disconnecting from NordVPN..."
    sudo nordvpn d >/dev/null
    
    # Original interactive guide
    printf "\n${GREEN}==================================================================${NC}\n"
    printf "${GREEN}Please follow the steps below to configure a new WireGuard tunnel in pfSense:${NC}\n"
    printf "${GREEN}==================================================================${NC}\n\n"
    printf "${BLUE}1. Interface Assignment:${NC}\n"
    printf "   - Navigate to Interfaces > Interface Assignments.\n"
    printf "   - Click 'Add' to create a new interface (e.g., OPT1:).\n"
    printf "   - Click on the newly added interface.\n"
    printf "   - Set the following:\n"
    printf "       Description: ${LIGHT_GREEN}WG_VPN${NC}\n"
    printf "       IP Address: ${LIGHT_GREEN}10.5.0.2/32${NC}\n"
    printf "       MSS: ${LIGHT_GREEN}1392${NC}\n"
    printf "       MTU: ${LIGHT_GREEN}1420${NC}\n"
    printf "   - Enable Interface, then Save.\n\n"
    printf "${BLUE}2. WireGuard Tunnel Configuration:${NC}\n"
    printf "   - VPN > WireGuard > Tunnels > Add\n"
    printf "       Description: ${LIGHT_GREEN}WG-NordVPN${NC}\n"
    printf "       Listen Port: ${LIGHT_GREEN}$listening_port${NC}\n"
    printf "       Private Key: ${LIGHT_GREEN}$private_key${NC}\n"
    printf "       Public Key: ${LIGHT_GREEN}$public_key${NC}\n\n"
    printf "${BLUE}3. Peer Configuration:${NC}\n"
    printf "   - Add Peer under this tunnel:\n"
    printf "       Description: ${LIGHT_GREEN}$server_name${NC}\n"
    printf "       Endpoint: ${LIGHT_GREEN}$server_name${NC}\n"
    printf "       Allowed IPs: ${LIGHT_GREEN}0.0.0.0/0${NC}\n"
    printf "       Persistent Keepalive: ${LIGHT_GREEN}15${NC}\n\n"
    printf "${BLUE}4. Static Route:${NC}\n"
    printf "   - System > Routing > Static Routes > Add\n"
    printf "       Destination network: ${LIGHT_GREEN}$endpoint_ip/32${NC}\n"
    printf "       Gateway: ${LIGHT_GREEN}WAN PPOE${NC}\n"
    printf "       Description: ${LIGHT_GREEN}$server_name${NC}\n\n"
    printf "${GREEN}==================================================================${NC}\n"
    printf "\n"
}

# Execute based on choice
if [[ "$choice" == "1" ]]; then
    edit_existing_connection
else
    create_new_connection
fi

# Optionally reset tech
printf "${CYAN}Reset NordVPN technology to OPENVPN?${NC}\n"
read -rp "$(printf "${YELLOW}Enter 'o' for OPENVPN or 'n' to keep NORDLYNX [o/n]: ${NC}")" tech_choice
if [[ "${tech_choice,,}" == "o" ]]; then
    info_msg "Setting technology to OpenVPN..."
    sudo nordvpn set technology openvpn &>/dev/null
    success_msg "Now using OpenVPN."
else
    success_msg "Keeping NordLynx."
fi

printf "\n"
success_msg "Script execution completed."
