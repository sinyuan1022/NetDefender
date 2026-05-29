
#!/bin/bash

# NetDefender Setup Script
# This script sets up the NetDefender environment with Open vSwitch, Docker, and Ryu SDN controller

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} \\$1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} \\$1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} \\$1"
}

print_prompt() {
    echo -e "${BLUE}[INPUT]${NC} \\$1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_status "Starting NetDefender setup..."

# Update and upgrade system
print_status "Updating system packages..."
apt update
apt upgrade -y

# Install required packages
print_status "Installing required packages..."
apt install -y \
    openvswitch-switch \
    vim \
    net-tools \
    iptables-persistent \
    isc-dhcp-client \
    dhcpcd5 \
    htop \
    ifmetric \
    screen \
    dnsmasq \
	docker.io \
	isc-dhcp-client \
	python3 \
	python3-pip


# Install pip for Python 3.9
print_status "Installing pip for Python 3.9..."
python3 get-pip.py

# Install Python packages
print_status "Installing Python packages..."
pip install os-ken==3.1.1 docker scapy tabulate

docker plugin install --grant-all-permissions ghcr.io/claymore666/docker-net-dhcp:latest

# Run image check
print_status "Running image check..."
python3 imagecheck.py

# Create virtual ethernet pair
print_status "Creating virtual ethernet pair..."
if ! ip link show veth0 &>/dev/null && ! ip link show veth1 &>/dev/null; then
    echo "Creating veth pair: veth0 <-> veth1"
    ip link add veth0 type veth peer name veth1
else
    echo "veth0 or veth1 already exists, skipping creation."
fi
# Assign IP to veth0 if not already assigned
while true; do
    print_prompt "Enter IP/prefix for veth0 (e.g., 192.168.100.1/24):"
    read -r VETH0_CIDR
    # Validate format
    if [[ ! "$VETH0_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
        print_error "Invalid format. Try again."
        continue
    fi
    # Skip if already assigned
    if ip addr show veth0 2>/dev/null | grep -q "$VETH0_CIDR"; then
        print_warning "$VETH0_CIDR already assigned to veth0, skipping."
        break
    fi
    # Apply
    if ip addr add "$VETH0_CIDR" dev veth0; then
        print_status "Assigned $VETH0_CIDR to veth0."
        break
    else
        print_error "Failed to assign IP. Try again."
    fi
# Create bridge my-bridge if not exists
if ! ip link show my-bridge &>/dev/null; then
    echo "Creating bridge: my-bridge"
    ip link add my-bridge type bridge
else
    echo "Bridge my-bridge already exists, skipping creation."
fi
# Bring up my-bridge if not already up
if ! ip link show my-bridge | grep -q "UP"; then
    echo "Bringing up my-bridge"
    ip link set my-bridge up
else
    echo "my-bridge is already UP, skipping."
fi
# Attach veth1 to my-bridge if not already attached
if ! bridge link show | grep -q "veth1"; then
    echo "Attaching veth1 to my-bridge"
    ip link set veth1 master my-bridge
else
    echo "veth1 is already attached to a bridge, skipping."
fi
# Bring up veth0 if not already up
if ! ip link show veth0 | grep -q "UP"; then
    echo "Bringing up veth0"
    ip link set veth0 up
else
    echo "veth0 is already UP, skipping."
fi
# Bring up veth1 if not already up
if ! ip link show veth1 | grep -q "UP"; then
    echo "Bringing up veth1"
    ip link set veth1 up
else
    echo "veth1 is already UP, skipping."
fi

# Configure iptables
print_status "Configuring iptables..."
iptables -A FORWARD -i my-bridge -j ACCEPT
iptables -I FORWARD -o my-bridge -j ACCEPT
iptables -P FORWARD ACCEPT

# Enable IP forwarding
print_status "Enabling IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
    if grep -q "^#net.ipv4.ip_forward" /etc/sysctl.conf; then
        sed -i 's/^#net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    elif grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
        sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    else
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
fi
sysctl -p

# Configure dnsmasq
print_status "Configuring dnsmasq..."
DNSMASQ_PORT=0
DNSMASQ_INTERFACE=veth0
DNSMASQ_NO_DHCP_INTERFACE=br0
DNSMASQ_LOOPBACK=127.0.0.1
#Interactive DNSMASQ DHCP configuration
DNSMASQ_CONFIGURED=false
while [ "$DNSMASQ_CONFIGURED" = false ]; do
    print_status "Configuring dnsmasq DHCP..."
    #Listen address
    print_prompt "Enter the listen address for dnsmasq on veth0 (e.g., 192.168.100.1):"
    read -r DNSMASQ_LISTEN
    if [[ ! "$DNSMASQ_LISTEN" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        print_error "Invalid IP address format. Please try again."
        continue
    fi
    #DHCP range
    print_prompt "Enter the DHCP range start IP (e.g., 192.168.100.2):"
    read -r DHCP_RANGE_START
    print_prompt "Enter the DHCP range end IP (e.g., 192.168.100.254):"
    read -r DHCP_RANGE_END
    print_prompt "Enter the subnet mask (e.g., 255.255.255.0):"
    read -r DHCP_SUBNET
    print_prompt "Enter the DHCP lease time (e.g., 1h, 12h, 24h):"
    read -r DHCP_LEASE
    #Gateway (option 3)
    print_prompt "Enter the default gateway for DHCP clients (e.g., 192.168.100.1):"
    read -r DHCP_GATEWAY
    #Broadcast (option 28) — auto-calculate or manual
    print_prompt "Enter broadcast address (e.g., 192.168.100.255) or press Enter to auto-calculate:"
    read -r DHCP_BROADCAST
    if [ -z "$DHCP_BROADCAST" ]; then
        # Auto-calculate broadcast from listen address /24
        DHCP_BROADCAST=$(echo "$DNSMASQ_LISTEN" | awk -F. '{print $1"."$2"."$3".255"}')
        print_status "Auto-calculated broadcast: $DHCP_BROADCAST"
    fi
    #DNS servers (option 6)
    print_prompt "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4):"
    read -r DHCP_DNS_INPUT
    DHCP_DNS1=$(echo "$DHCP_DNS_INPUT" | cut -d',' -f1 | tr -d ' ')
    DHCP_DNS2=$(echo "$DHCP_DNS_INPUT" | cut -d',' -f2 | tr -d ' ')
    #Preview
    echo ""
    print_warning "---- Preview: /etc/dnsmasq.conf ----"
    cat << EOF
port=$DNSMASQ_PORT
interface=$DNSMASQ_INTERFACE
no-dhcp-interface=$DNSMASQ_NO_DHCP_INTERFACE
listen-address=$DNSMASQ_LISTEN
listen-address=$DNSMASQ_LOOPBACK
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_SUBNET,$DHCP_LEASE
dhcp-option=3,$DHCP_GATEWAY
dhcp-option=28,$DHCP_BROADCAST
dhcp-option=6,$DHCP_DNS1,$DHCP_DNS2
EOF
    echo "------------------------------------"
    echo ""
    #Confirm
    print_prompt "Apply this configuration? (y/n):"
    read -r CONFIRM
    if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
        cat > /etc/dnsmasq.conf << EOF
port=$DNSMASQ_PORT
interface=$DNSMASQ_INTERFACE
no-dhcp-interface=$DNSMASQ_NO_DHCP_INTERFACE
listen-address=$DNSMASQ_LISTEN
listen-address=$DNSMASQ_LOOPBACK
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_SUBNET,$DHCP_LEASE
dhcp-option=3,$DHCP_GATEWAY
dhcp-option=28,$DHCP_BROADCAST
dhcp-option=6,$DHCP_DNS1,$DHCP_DNS2
EOF
        print_status "dnsmasq.conf written successfully."
        DNSMASQ_CONFIGURED=true
    else
        print_warning "Configuration cancelled. Starting over..."
        echo ""
    fi
done
# Configure netplan interactively with loop for re-entry
print_status "backup netplan..."
cp /etc/netplan/*.yaml /etc/netplan/01-network-manager-all.yaml.backup
touch /etc/netplan/01-network-manager-all.yaml
NETPLAN_CONFIGURED=false
while [ "$NETPLAN_CONFIGURED" = false ]; do
    print_status "Configuring netplan..."
    print_warning "Available network interfaces:"
    # Fixed the awk command
    ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ' | grep -v lo

    # Get primary interface for bridge
    print_prompt "Enter the primary network interface name for bridge (e.g., ens33, eth0):"
    read -r PRIMARY_INTERFACE

    # Get bridge network configuration
    print_prompt "Enter the IP address for br0 bridge (e.g., 192.168.254.137/24):"
    read -r BR0_IP

    print_prompt "Enter the default gateway for br0 (e.g., 192.168.254.2):"
    read -r BR0_GATEWAY

    print_prompt "Enter DNS servers for br0 (comma-separated, e.g., 8.8.8.8,8.8.4.4):"
    read -r BR0_DNS
    BR0_DNS1=$(echo "$BR0_DNS" | cut -d',' -f1 | tr -d ' ')
    BR0_DNS2=$(echo "$BR0_DNS" | cut -d',' -f2 | tr -d ' ')

    # Optional secondary interface configuration
    print_prompt "Do you want to configure a secondary interface? (y/n):"
    read -r CONFIGURE_SECONDARY

    # Start building netplan configuration
    cat > /etc/netplan/01-network-manager-all.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $PRIMARY_INTERFACE:
      dhcp4: no
EOF

    # Add secondary interface if requested
    if [[ "$CONFIGURE_SECONDARY" == "y" ]] || [[ "$CONFIGURE_SECONDARY" == "Y" ]]; then
        print_prompt "Enter the secondary network interface name (e.g., ens34, eth1):"
        read -r SECONDARY_INTERFACE
        
        print_prompt "Enter the IP address for $SECONDARY_INTERFACE (e.g., 192.168.1.104/24):"
        read -r SECONDARY_IP
        
        print_prompt "Enter the default gateway for $SECONDARY_INTERFACE (e.g., 192.168.1.1):"
        read -r SECONDARY_GATEWAY
        
        print_prompt "Enter the metric for $SECONDARY_INTERFACE route (e.g., 100):"
        read -r SECONDARY_METRIC
        
        print_prompt "Enter DNS servers for $SECONDARY_INTERFACE (comma-separated, e.g., 8.8.8.8,8.8.4.4):"
        read -r SECONDARY_DNS
        SECONDARY_DNS1=$(echo "$SECONDARY_DNS" | cut -d',' -f1 | tr -d ' ')
        SECONDARY_DNS2=$(echo "$SECONDARY_DNS" | cut -d',' -f2 | tr -d ' ')
        
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
    $SECONDARY_INTERFACE:
      addresses:
        - $SECONDARY_IP
EOF
        
        # Add nameservers for secondary interface
        if [[ -n "$SECONDARY_DNS2" ]]; then
            cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $SECONDARY_DNS1
          - $SECONDARY_DNS2
EOF
        else
            cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $SECONDARY_DNS1
EOF
        fi
        
        # Add routes for secondary interface
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      routes:
        - to: default
          via: $SECONDARY_GATEWAY
          metric: $SECONDARY_METRIC
EOF
    fi

    # Add bridge configuration
    cat >> /etc/netplan/01-network-manager-all.yaml << EOF
  bridges:
    br0:
      interfaces: [$PRIMARY_INTERFACE]
      addresses:
        - $BR0_IP
EOF

    # Add nameservers only if DNS2 exists
    if [[ -n "$BR0_DNS2" ]]; then
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $BR0_DNS1
          - $BR0_DNS2
EOF
    else
        cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      nameservers:
        addresses:
          - $BR0_DNS1
EOF
    fi

    # Add the rest of bridge configuration
    cat >> /etc/netplan/01-network-manager-all.yaml << EOF
      routes:
        - to: default
          via: $BR0_GATEWAY
      parameters:
        stp: false
        forward-delay: 0
      openvswitch:
        fail-mode: standalone
        controller:
          addresses:
            - tcp:127.0.0.1:6653
EOF

    # Display the configuration for review
    echo ""
    print_status "Generated netplan configuration:"
    echo "========================================="
    cat /etc/netplan/01-network-manager-all.yaml
    echo "========================================="
    echo ""

    print_prompt "Does this configuration look correct? (y/n):"
    read -r CONFIRM

    if [[ "$CONFIRM" == "y" ]] || [[ "$CONFIRM" == "Y" ]]; then
        NETPLAN_CONFIGURED=true
        print_status "Configuration accepted, proceeding..."
    else
        print_warning "Configuration rejected, let's try again..."
        echo ""
    fi
done

# Set proper permissions for netplan config
chmod 600 /etc/netplan/*yaml

# Apply netplan configuration
print_status "Applying netplan configuration..."
systemctl restart systemd-networkd
netplan apply
ovs-vsctl set bridge br0 protocols=OpenFlow13

# Restart dnsmasq
print_status "Restarting dnsmasq service..."
systemctl restart dnsmasq

# Configure DHCP on interfaces
print_status "Configuring DHCP on interfaces..."
dhclient veth1 || print_warning "dhclient veth1 failed, continuing..."
dhcpcd my-bridge

# Create Docker network
print_status "Creating Docker network..."
docker network create -d ghcr.io/claymore666/docker-net-dhcp:latest \
    --ipam-driver null \
    -o bridge=my-bridge \
    my-dhcp-net || print_warning "Docker network may already exist"

# Start Ryu controller in screen session
print_status "Starting Ryu controller in screen session..."
screen -dmS osken osken-manager ovs.py

print_status "NetDefender setup completed successfully!"
print_status "Ryu controller is running in a screen session named 'osken'"
print_status "To attach to the session, use: screen -r osken"

