#!/bin/bash

# =============================================
# USER CONFIGURATION SECTION
# =============================================

# >>>>> API Keys and Script Settings <<<<<

# Your AbuseIPDB API key (get one free at https://www.abuseipdb.com/account/api)
abuseipdb_api_key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # Register free at https://www.abuseipdb.com/account/api

# Your Spamhaus Lookup API key (see https://www.spamhaus.com/apikey/)
spamhaus_api_key="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

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

# ----- AbuseIPDB API lookup -----
abuseipdb_check(){
    local ip="$1"
    [[ -z "$abuseipdb_api_key" || "$abuseipdb_api_key" == "xxx" ]] && { echo "API key not set"; return 2; }
    local resp
    resp=$(curl -4 -sG https://api.abuseipdb.com/api/v2/check \
      --data-urlencode "ipAddress=$ip" \
      --data-urlencode "maxAgeInDays=90" \
      -H "Key: $abuseipdb_api_key" \
      -H "Accept: application/json" \
      --connect-timeout 10 \
      --max-time 15 2>/dev/null)
    
    if [[ $? -ne 0 || -z "$resp" ]]; then
        echo "Connection error"; return 2
    fi
    
    # Check for API errors
    if echo "$resp" | grep -q '"errors"'; then
        echo "API error"; return 2
    fi
    
    local reports=$(echo "$resp" | grep -o '"totalReports":[0-9]*' | grep -o '[0-9]*')
    local score=$(echo "$resp"   | grep -o '"abuseConfidenceScore":[0-9]*' | grep -o '[0-9]*')
    [[ -z "$reports" ]] && { echo "Parse error"; return 2; }
    (( reports>0 )) && { echo "⚠️ Listed ($reports reports, score:$score)"; return 1; }
    echo "Not listed"; return 0
}

# ----- Spamhaus API with improved fallback -----
spamhaus_check(){
    local ip="$1"
    
    # Try API first if key is provided
    if [[ -n "$spamhaus_api_key" && "$spamhaus_api_key" != "xxx" ]]; then
        local url="https://apibl.spamhaus.net/lookup/v1/zen/$ip"
        local raw
        raw=$(curl -4 -s -w "\n%{http_code}" \
          -H "Authorization: Bearer $spamhaus_api_key" \
          -H "Accept: application/json" \
          --connect-timeout 10 \
          --max-time 15 \
          "$url" 2>/dev/null)
        
        if [[ $? -eq 0 && -n "$raw" ]]; then
            local code="${raw##*$'\n'}"
            local body="${raw%$'\n'*}"
            
            if [[ "$code" == "200" ]]; then
                local codes
                codes=$(echo "$body" | grep -oP '"resp":\[\K[^\]]*' 2>/dev/null)
                [[ -z "$codes" ]] && codes="unknown"
                echo "⚠️ Listed (API: $codes)"; return 1
            elif [[ "$code" == "404" ]]; then
                echo "Not listed"; return 0
            fi
        fi
    fi
    
    # Fallback to alternative DNSBL or skip
    warning_msg "Spamhaus API unavailable - skipping Spamhaus check"
    echo "Skipped (API unavailable)"; return 2
}

# ----- Additional blacklist checks -----
# Check against other reliable DNSBLs
additional_dnsbl_check(){
    local ip="$1"
    local listed=0
    
    # Check Barracuda
    IFS=. read -r a b c d <<<"$ip"
    if timeout 5 dig +short A "$d.$c.$b.$a.b.barracudacentral.org" 2>/dev/null | grep -qE '^127\.'; then
        echo "⚠️ Listed (Barracuda)"; return 1
    fi
    
    # Check SURBL (for completeness, though it's more for domains)
    if timeout 5 dig +short A "$d.$c.$b.$a.multi.surbl.org" 2>/dev/null | grep -qE '^127\.'; then
        echo "⚠️ Listed (SURBL)"; return 1
    fi
    
    echo "Not listed"; return 0
}

# ----- Combined blacklist check -----
check_ip_blacklists(){
    info_msg "Checking if your VPN exit IP is on major blacklists..."
    local ip
    ip=$(curl -4 -m5 -s https://api.ipify.org 2>/dev/null)
    
    if [[ -z "$ip" ]]; then
        # Try alternative IP detection services
        ip=$(curl -4 -m5 -s https://ipecho.net/plain 2>/dev/null)
        [[ -z "$ip" ]] && ip=$(curl -4 -m5 -s https://icanhazip.com 2>/dev/null)
    fi
    
    [[ -z "$ip" ]] && { warning_msg "Could not determine public IP"; return 2; }
    
    # Validate IP format
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        warning_msg "Invalid IP format received: $ip"; return 2
    fi
    
    printf "\n${CYAN}Current public IP: ${LIGHT_GREEN}%s${NC}\n\n" "$ip"
    
    local a_status s_status d_status a_ret s_ret d_ret
    a_status=$(abuseipdb_check "$ip"); a_ret=$?
    s_status=$(spamhaus_check   "$ip"); s_ret=$?
    d_status=$(additional_dnsbl_check "$ip"); d_ret=$?
    
    printf "${YELLOW}%-15s | %-30s${NC}\n" "Service" "Status"
    printf "${YELLOW}%-15s | %-30s${NC}\n" "---------------" "------------------------------"
    printf "%-15s | %-30s\n" "AbuseIPDB" "$a_status"
    printf "%-15s | %-30s\n" "Spamhaus" "$s_status"
    printf "%-15s | %-30s\n" "Other DNSBLs" "$d_status"
    printf "\n"
    
    # Consider IP clean if AbuseIPDB is clean AND either Spamhaus is clean OR unavailable
    # AND additional DNSBLs are clean
    if [[ $a_ret -eq 0 && ($s_ret -eq 0 || $s_ret -eq 2) && $d_ret -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

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
        
        if check_ip_blacklists; then
            success_msg "Clean exit IP obtained."
            return 0
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
for tool in nordvpn wg curl dig; do
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

# Check API keys
if [[ "$abuseipdb_api_key" == "xxx" ]]; then
    warning_msg "AbuseIPDB API key not configured - checks will be skipped"
fi
if [[ "$spamhaus_api_key" == "xxx" ]]; then
    warning_msg "Spamhaus API key not configured - using fallback methods"
fi

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
    
    nord_connect_until_clean "$vpn_target"
    
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
    
    nord_connect_until_clean "$vpn_target"
    
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
