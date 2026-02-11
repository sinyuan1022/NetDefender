# NetDefender

## 📋 Overview

**NetDefender** is a comprehensive network defense and traffic redirection platform that seamlessly integrates **Software-Defined Networking (SDN)** and **Intrusion Detection Systems (IDS)**. 

### Key Features

- **Core Controller**: Built on the OSKen controller framework
- **Packet Forwarding**: Utilizes Open vSwitch (OVS) for intelligent packet forwarding and policy enforcement
- **Intrusion Detection**: Integrates with Snort IDS for real-time threat detection
- **Dynamic Traffic Redirection**: Automatically redirects suspicious traffic to containerized honeypots
- **Container Orchestration**: Supports basic container lifecycle management for honeypot services
- **Extensible Policies**: Flexible policy framework for customizable defense strategies
- **Observable Environment**: Provides comprehensive visibility into network traffic and security events

---

## 🖥️ System Requirements

### Ryu Server
- **Operating System**: Ubuntu 22.04
- **Python Version**: Python 3.9

### Snort Server
- **Operating System**: Ubuntu 22.04
- **Python Version**: Python 3.9+

---

## ⚠️ Important Notes

> **Installation Order**: The Ryu server must be installed and configured **before** the Snort server.

> **Internet Connection**: Ensure both servers have active internet connectivity before beginning the installation process.

> **Comment Syntax**: Lines beginning with `#` are comments in configuration files.

---

## 🌐 Network Architecture

The following diagram illustrates the NetDefender network topology:

<img width="1019" height="637" alt="NetDefender Network Architecture" src="https://github.com/user-attachments/assets/3c2be482-1a8f-49ce-82ce-e933007d856f" />

---

## 🍯 Honeypot Configuration

NetDefender uses a JSON-based configuration file to define honeypot containers. The configuration supports multiple honeypot types with flexible port mapping.

### Complete Configuration Example

```json
{
  "containers": [
    {
      "image_name": "cowrie/cowrie",
      "name": "ssh",
      "ports": [
        {
          "host_port": 22,
          "container_port": 2222,
          "protocol": "tcp"
        }
      ],
      "command": "",
      "multi": "yes", 
      "max": 10,
      "max_containers": 10,
      "send_response": "yes"
    },
    {
      "image_name": "dinotools/dionaea",
      "name": "dionaea",
      "ports": [
        {"host_port": 21, "container_port": 21, "protocol": "tcp"},
        {"host_port": 42, "container_port": 42, "protocol": "tcp"},
        {"host_port": 69, "container_port": 69, "protocol": "udp"},
        {"host_port": 80, "container_port": 80, "protocol": "tcp"},
        {"host_port": 135, "container_port": 135, "protocol": "tcp"},
        {"host_port": 443, "container_port": 443, "protocol": "tcp"},
        {"host_port": 445, "container_port": 445, "protocol": "tcp"},
        {"host_port": 1433, "container_port": 1433, "protocol": "tcp"},
        {"host_port": 1723, "container_port": 1723, "protocol": "tcp"},
        {"host_port": 1883, "container_port": 1883, "protocol": "tcp"},
        {"host_port": 1900, "container_port": 1900, "protocol": "udp"},
        {"host_port": 3306, "container_port": 3306, "protocol": "tcp"},
        {"host_port": 5060, "container_port": 5060, "protocol": "tcp"},
        {"host_port": 5060, "container_port": 5060, "protocol": "udp"},
        {"host_port": 5061, "container_port": 5061, "protocol": "tcp"},
        {"host_port": 11211, "container_port": 11211, "protocol": "tcp"}
      ],
      "command": "",
      "multi": "yes",
      "max": 10,
      "max_containers": 10,
      "send_response": "yes"
    }
  ]
}
```

---

## 📖 Configuration Parameters

### Container-Level Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `image_name` | String | Yes | Docker image name for the honeypot container |
| `name` | String | Yes | Unique identifier for the container instance |
| `ports` | Array | Yes | Array of port mapping objects defining network access |
| `command` | String | No | Additional Docker command-line arguments (Delete this line if it is not needed) |
| `multi` | String | No | Enable multiple container instances (`yes`/`no`) (Default: no)|
| `max` | Integer | No | Maximum number of concurrent connections per container (Default: 10) |
| `max_containers` | Integer | No | Maximum total number of container instances allowed (Primary is not included) (Default: 10)|
| `send_response` | String | No | Whether the honeypot should send response packets (`yes`/`no`) (Default: no)|

### Port Mapping Parameters

Each object in the `ports` array must contain the following fields:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `host_port` | Integer | Yes | The external network port where incoming packets are received |
| `container_port` | Integer | Yes | The internal container port for traffic redirection |
| `protocol` | String | Yes | Network protocol (`tcp` or `udp`) |

---

## 🎯 Honeypot Types

### 1. SSH Honeypot (Cowrie)

**Purpose**: Emulates an SSH/Telnet service to capture brute-force attacks and shell interactions.

- **Image**: `cowrie/cowrie`
- **Monitored Port**: 22 (SSH)
- **Internal Port**: 2222
- **Use Case**: Capturing SSH login attempts, commands, and file downloads

### 2. Multi-Service Honeypot (Dionaea)

**Purpose**: A comprehensive honeypot that emulates multiple vulnerable services simultaneously.

- **Image**: `dinotools/dionaea`
- **Monitored Services**:
  - **FTP** (21): File Transfer Protocol
  - **WINS** (42): Windows Internet Name Service
  - **TFTP** (69, UDP): Trivial File Transfer Protocol
  - **HTTP** (80): Web traffic
  - **RPC** (135): Remote Procedure Call
  - **HTTPS** (443): Secure web traffic
  - **SMB** (445): Server Message Block
  - **MSSQL** (1433): Microsoft SQL Server
  - **PPTP** (1723): Point-to-Point Tunneling Protocol
  - **MQTT** (1883): Message Queuing Telemetry Transport
  - **UPnP** (1900, UDP): Universal Plug and Play
  - **MySQL** (3306): MySQL Database
  - **SIP** (5060, TCP/UDP & 5061): Session Initiation Protocol
  - **Memcached** (11211): Distributed memory caching system

---

## 🚀 Installation Guide

### 1. Ryu Server Installation

Execute the following commands to install the Ryu controller:

```bash
# Switch to root user
sudo -s

# Install Git
apt install git -y

# Clone the NetDefender repository
git clone https://github.com/sinyuan1022/NetDefender.git

# Navigate to the Ryu directory
cd ./NetDefender/ryu/

# Run the Ryu installation script
bash ./ryu_install.sh
```

---

### 2. Snort Server Installation

**Prerequisites**: Complete the Ryu server installation first.

Execute the following commands to install the Snort IDS:

```bash
# Switch to root user
sudo -s

# Install Git
apt install git -y

# Clone the NetDefender repository
git clone https://github.com/sinyuan1022/NetDefender.git

# Navigate to the Snort directory
cd ./NetDefender/snort/

# Run the Snort installation script
bash ./snort_install.sh
```

---

### 3. Single Server Deployment (Optional)

> **Note**: This deployment mode is **currently not enabled** by default. Use this option only if you want to combine both Ryu and Snort on a single server.

```bash
# Switch to root user
sudo -s

# Install Git
apt install git -y

# Clone the NetDefender repository
git clone https://github.com/sinyuan1022/NetDefender.git

# Navigate to the root directory
cd ./NetDefender/

# Run the combined installation script
bash ./singel.sh
```

---

## 🔧 Configuration Best Practices

### Port Mapping Strategy

**Single-Port Honeypots**: Use when targeting specific services like SSH or Telnet.

```json
{
  "image_name": "cowrie/cowrie",
  "name": "ssh",
  "ports": [
    {"host_port": 22, "container_port": 2222, "protocol": "tcp"}
  ]
}
```

**Multi-Port Honeypots**: Use when simulating comprehensive network services or vulnerable servers.

```json
{
  "image_name": "dinotools/dionaea",
  "name": "dionaea",
  "ports": [
    {"host_port": 80, "container_port": 80, "protocol": "tcp"},
    {"host_port": 443, "container_port": 443, "protocol": "tcp"}
  ]
}
```

### Scaling Configuration

- **`multi: "yes"`**: Enables dynamic container spawning for high-traffic scenarios
- **`max: 10`**: Limits concurrent connections per container to prevent resource exhaustion
- **`max_containers: 10`**: Sets an upper bound on total container instances

### Response Behavior

- **`send_response: "yes"`**: Honeypot actively responds to attackers (more realistic)
- **`send_response: "no"`**: Silent monitoring mode (useful for specific detection scenarios)

---

## 📚 How It Works

### Traffic Flow

1. **Traffic Monitoring**: Open vSwitch forwards network traffic to the Ryu controller
2. **Threat Detection**: Snort IDS analyzes traffic patterns and generates alerts
3. **Policy Evaluation**: The controller evaluates traffic against configured policies
4. **Port Matching**: Incoming traffic is matched against configured `host_port` values
5. **Dynamic Redirection**: Suspicious traffic is redirected to appropriate honeypot containers
6. **Container Management**: The system automatically spawns and manages honeypot instances based on load
7. **Response Generation**: Honeypots interact with attackers while logging all activities
8. **Data Collection**: All interactions are captured for analysis and threat intelligence

---

## 🎓 Use Cases

### Security Research
Create controlled environments for studying attack patterns, malware behavior, and exploitation techniques across multiple protocols.
### Threat Intelligence
Collect and analyze malicious traffic data from SSH brute-force attempts, SMB exploits, SQL injection attacks, and IoT botnet activities.
### Network Defense
Implement proactive defense mechanisms by redirecting attackers to honeypots while protecting production systems.

---

## 🔗 Resources

- **Repository**: [https://github.com/sinyuan1022/NetDefender](https://github.com/sinyuan1022/NetDefender)
- **OSKen/Ryu Documentation**: Component-based SDN controller framework
- **Open vSwitch**: Production-quality multilayer virtual switch
- **Snort**: Open-source network intrusion detection and prevention system
- **Cowrie**: SSH/Telnet honeypot designed to log brute-force attacks
- **Dionaea**: Low-interaction honeypot that captures malware and exploits

---

*For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/sinyuan1022/NetDefender).*
