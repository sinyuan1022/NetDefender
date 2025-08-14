
#!/bin/bash

# NetDefender Setup Script
# This script automates the installation and configuration of NetDefender with Snort

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} \\$1"
}

print_error() {
    echo -e "${RED}[!]${NC} \\$1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} \\$1"
}
print_prompt() {
    echo -e "${BLUE}[INPUT]${NC} \\$1"
}


# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run this script as root or with sudo"
    exit 1
fi

# Update package list
print_status "Updating package list..."
apt update

# Install required packages
print_status "Installing required packages..."
apt install python3 python3-pip snort vim screen net-tools -y

if [ $? -ne 0 ]; then
    print_error "Failed to install packages"
    exit 1
fi

# Set network interface to promiscuous mode
print_prompt "Enter the Setting interface name (e.g., ens33):"
read -r INTERFACE
print_status "Setting $INTERFACE to promiscuous mode..."
ifconfig $INTERFACE promisc

if [ $? -ne 0 ]; then
    print_error "Failed to set promiscuous mode on ens33"
    print_warning "Make sure the interface ens33 exists"
fi

# Start Snort in screen session
print_status "Starting Snort in screen session..."
screen -dmS snort snort -i $INTERFACE -A unsock -l /tmp -c /etc/snort/snort.conf

if [ $? -ne 0 ]; then
    print_error "Failed to start Snort"
    exit 1
fi

# Modify pigrelay.py
print_status "Configuring pigrelay.py..."

# Prompt user for Controller IP
read -p "Enter Controller IP (default: 127.0.0.1): " CONTROLLER_IP
CONTROLLER_IP=${CONTROLLER_IP:-127.0.0.1}

# Use sed to modify the CONTROLLER_IP in pigrelay.py
if [ -f "./pigrelay.py" ]; then
    sed -i "s/CONTROLLER_IP = .*/CONTROLLER_IP = '$CONTROLLER_IP'/g" ./pigrelay.py
    print_status "Updated CONTROLLER_IP to $CONTROLLER_IP"
else
    print_error "pigrelay.py not found"
    exit 1
fi

# Display the current configuration
print_status "Current pigrelay.py configuration:"
grep "CONTROLLER_IP" ./pigrelay.py

# Ask if user wants to run pigrelay.py now
read -p "Do you want to start pigrelay.py now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_status "Starting pigrelay.py..."
    python3 pigrelay.py
else
    print_status "Setup complete!"
    print_status "To start pigrelay.py later, run:"
    echo "    cd $(pwd)"
    echo "    python3 pigrelay.py"
    echo
    print_status "To check Snort status, run:"
    echo "    screen -r snort"
fi

