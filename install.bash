
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
    dhcpcd5 \
    htop \
    ifmetric \
    software-properties-common \
    git \
    screen \
    dnsmasq

# Install specific Docker version
print_status "Installing Docker version 20.10.21..."
apt install -y docker.io=20.10.21-0ubuntu1~22.04.3

# Add Python PPA
print_status "Adding Python PPA repository..."
add-apt-repository -y ppa:deadsnakes/ppa
apt update

# Clone NetDefender repository
print_status "Cloning NetDefender repository..."
if [ -d "NetDefender" ]; then
    print_warning "NetDefender directory already exists, skipping clone"
else
    git clone https://github.com/sinyuan1022/NetDefender.git
fi

# Navigate to ryu directory
cd ./NetDefender/ryu/

# Install Python 3.9
print_status "Installing Python 3.9..."
apt install -y python3.9 python3.9-distutils

# Install pip for Python 3.9
print_status "Installing pip for Python 3.9..."
python3.9 get-pip.py

# Install Python packages
print_status "Installing Python packages..."
pip install setuptools==67.6.1
pip install ryu docker scapy
pip install eventlet==0.30.2

# Install Docker network plugin
print_status "Installing Docker network DHCP plugin..."
docker plugin install --grant-all-permissions ghcr.io/devplayer0/docker-net-dhcp:release-linux-amd64

# Run image check
print_status "Running image check..."
python3.9 imagecheck.py

# Create virtual ethernet pair
print_status "Creating virtual ethernet pair..."
ip link add veth0 type veth peer name veth1
ip addr add 192.168.100.1/24 dev veth0
ip link set veth0 up
ip link set veth1 up

# Create bridge
print_status "Creating bridge..."
ip link add my-bridge type bridge
ip link set my-bridge up
ip link set veth1 master my-bridge

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
cat > /etc/dnsmasq.conf << EOF
port=0
interface=veth0
no-dhcp-interface=br0
listen-address=192.168.100.1
listen-address=127.0.0.1
dhcp-range=192.168.100.2,192.168.100.254,255.255.255.0,1h
dhcp-option=3,192.168.100.1
dhcp-option=28,192.168.100.255
dhcp-option=6,8.8.8.8,8.8.4.4
EOF
# Configure netplan interactively with loop for re-entry
print_status "backup netplan..."
cp /etc/netplan/01-network-manager-all.yaml /etc/netplan/01-network-manager-all.yaml.backup
vim /etc/netplan/01-network-manager-all.yaml
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

# Restart dnsmasq
print_status "Restarting dnsmasq service..."
systemctl restart dnsmasq

# Configure DHCP on interfaces
print_status "Configuring DHCP on interfaces..."
dhclient veth1 || print_warning "dhclient veth1 failed, continuing..."
dhcpcd my-bridge || print_warning "dhcpcd my-bridge failed, continuing..."

# Create Docker network
print_status "Creating Docker network..."
docker network create -d ghcr.io/devplayer0/docker-net-dhcp:release-linux-amd64 \
    --ipam-driver null \
    -o bridge=my-bridge \
    my-dhcp-net || print_warning "Docker network may already exist"

# Start Ryu controller in screen session
print_status "Starting Ryu controller in screen session..."
screen -dmS ryu ryu-manager ovs.py

print_status "NetDefender setup completed successfully!"
print_status "Ryu controller is running in a screen session named 'ryu'"
print_status "To attach to the session, use: screen -r ryu"

