#!/bin/bash
# Network Security Configuration Script
# Implements restrictive firewall rules for development container

set -euo pipefail

echo "Configuring container network security..."

# Function to get network range from IP
get_network_range() {
    local ip="$1"
    local subnet_size="${2:-24}"  # Default to /24
    echo "$ip" | awk -F. -v subnet="$subnet_size" '{
        if (subnet == 24) printf "%d.%d.%d.0/%d\n", $1, $2, $3, subnet
        else if (subnet == 16) printf "%d.%d.0.0/%d\n", $1, $2, subnet
        else printf "%s/32\n", $0
    }'
}

# Configuration
ALLOWED_SERVICES=(
    "github.com"
    "api.github.com"
    "plugins.gradle.org"
    "registry.npmjs.org"
    "api.anthropic.com"
    "marketplace.visualstudio.com"
    "vscode.blob.core.windows.net"
    "update.code.visualstudio.com"
)

# Initialize firewall - clear existing rules
echo "Initializing firewall configuration..."
iptables -F || echo "Warning: Could not flush iptables rules"
iptables -X || echo "Warning: Could not delete custom chains"
ipset destroy permitted-hosts 2>/dev/null || echo "Creating new ipset"

# Create IP set for permitted destinations
ipset create permitted-hosts hash:net maxelem 1000

# Resolve service hostnames to IP addresses
echo "Resolving permitted service addresses..."
for service in "${ALLOWED_SERVICES[@]}"; do
    echo "Looking up: $service"

    # Use different DNS resolution approach
    addresses=$(nslookup "$service" 2>/dev/null | grep -A 10 "Name:" | grep "Address:" | awk '{print $2}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)

    if [[ -n "$addresses" ]]; then
        while IFS= read -r addr; do
            echo "  Adding address: $addr"
            ipset add permitted-hosts "$addr" 2>/dev/null || echo "  Warning: Could not add $addr"
        done <<< "$addresses"
    else
        echo "  Warning: No addresses found for $service"
    fi
done

# Add some basic GitHub IP ranges (since we can't fetch from API before firewall is set)
echo "Adding basic GitHub service ranges..."
# These are common GitHub IP ranges - may need updates over time
github_ranges=(
    "140.82.112.0/20"
    "143.55.64.0/20"
    "185.199.108.0/22"
    "192.30.252.0/22"
    "20.201.28.151/32"
    "20.205.243.166/32"
)

for range in "${github_ranges[@]}"; do
    echo "  Adding GitHub range: $range"
    ipset add permitted-hosts "$range" 2>/dev/null || true
done

# Maven repos - use broader network ranges due to frequent IP changes
for domain in "repo.maven.apache.org" "repo1.maven.org"; do
    echo "Resolving $domain (using /24 networks)..."
    ips=$(dig +noall +answer A "$domain" 2>/dev/null | awk '$4 == "A" {print $5}' || nslookup "$domain" 2>/dev/null | grep -A 10 "Name:" | grep "Address:" | awk '{print $2}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    if [ -z "$ips" ]; then
        echo "ERROR: Failed to resolve $domain"
        exit 1
    fi
    
    while read -r ip; do
        if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "ERROR: Invalid IP from DNS for $domain: $ip"
            exit 1
        fi
        network=$(get_network_range "$ip" 24)
        echo "Adding network $network for $domain"
        ipset add permitted-hosts "$network" 2>/dev/null || true
    done < <(echo "$ips")
done

# Detect container network configuration
container_gateway=$(ip route show default | head -1 | awk '{print $3}' 2>/dev/null || echo "")
if [[ -n "$container_gateway" ]]; then
    container_subnet=$(echo "$container_gateway" | sed 's/\.[0-9]*$/\.0\/24/')
    echo "Detected container network: $container_subnet"
    ipset add permitted-hosts "$container_subnet" 2>/dev/null || true
fi

# Configure basic connectivity rules
echo "Setting up network rules..."

# IMPORTANT: Allow established connections FIRST to preserve existing SSH/container connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow DNS queries
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 53 -j ACCEPT

# Allow SSH (to preserve container connection)
iptables -A INPUT -p tcp --sport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT

# Allow connections to permitted hosts
iptables -A OUTPUT -m set --match-set permitted-hosts dst -j ACCEPT

# Set default deny policy LAST
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Add explicit reject for better error messages
iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable

echo "Network security configuration completed"

# Basic connectivity test
echo "Testing network configuration..."
if timeout 3 wget -q --spider https://github.com 2>/dev/null; then
    echo "✓ GitHub connectivity verified"
else
    echo "✗ Warning: GitHub connectivity test failed"
fi

if timeout 3 wget -q --spider https://httpbin.org/ip 2>/dev/null; then
    echo "✗ Error: Unrestricted internet access detected"
    exit 1
else
    echo "✓ Internet access properly restricted"
fi

echo "Network security setup successful"
