# NetDefender

**NetDefender** is a comprehensive network defense and traffic redirection platform that seamlessly integrates **Software-Defined Networking (SDN)** and **Intrusion Detection Systems (IDS)**. Built on the OSKen controller, it leverages Open vSwitch for intelligent packet forwarding and policy enforcement while connecting with Snort for real-time intrusion detection. When traffic matches specific services or triggers security alerts, NetDefender automatically redirects the traffic to corresponding containerized services such as honeypots, providing an observable and controllable experimental defense environment.

---

## 🌟 Key Features

- **SDN Integration**: Utilizes OSKen controller for centralized network management
- **IDS Integration**: Connects with Snort for real-time threat detection
- **Traffic Redirection**: Automatically redirects suspicious traffic to honeypots
- **Container Management**: Supports basic lifecycle management for containerized services
- **Extensible Policies**: Flexible policy configuration for various defense scenarios
- **Dynamic Scaling**: Supports multiple concurrent container instances

---

## 🖥️ System Requirements

### Ryu Server
- **Operating System**: Ubuntu 22.04 LTS
- **Python Version**: Python 3.9

### Snort Server
- **Operating System**: Ubuntu 22.04 LTS
- **Python Version**: Python 3.9+

### Prerequisites
- Root or sudo access
- Active internet connection for installation
- Git installed on the system

---

## 🔔 Important Notes

> **⚠️ Installation Order**: The Ryu server **must** be configured and completed before setting up the Snort server.

> **🌐 Network Connectivity**: Ensure both servers have internet access before beginning the installation process.

> **💬 Comment Syntax**: Lines beginning with `#` are comments for documentation purposes.

---

## 🌐 Network Architecture

The following diagram illustrates the NetDefender network topology:

![Network Architecture](https://github.com/user-attachments/assets/3c2be482-1a8f-49ce-82ce-e933007d856f)


---

## ⚙️ Honeypot Configuration

NetDefender uses a JSON-based configuration file to define honeypot containers. Below is the configuration schema with detailed parameter descriptions:

```json
{
  "containers": [
    {
      "port": 22,
      "image_name": "cowrie/cowrie",
      "name": "ssh",
      "target_port": 2222,
      "command": "",
      "multi": "yes",
      "max": 10,
      "max_containers": 10,
      "send_response": "yes"
    },
    {
      // Additional honeypot configurations
    }
  ]
}
```

### Configuration Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| **port** | Integer | The port on which the honeypot listens for incoming traffic |
| **image_name** | String | Docker image name for the honeypot container (e.g., `cowrie/cowrie`) |
| **name** | String | Unique identifier for the container (can be any valid string) |
| **target_port** | Integer | The internal port that the container exposes |
| **command** | String | Additional Docker command arguments (optional) |
| **multi** | String | Whether to spawn multiple container instances (`"yes"` or `"no"`) |
| **max** | Integer | Maximum number of concurrent connections allowed |
| **max_containers** | Integer | Maximum number of container instances that can be spawned (excluding the primary container) |
| **send_response** | String | Whether to send response packets back to the source (`"yes"` or `"no"`) |

---

## 📦 Installation Guide

### Option 1: 
### Ryu Server Setup

Execute the following commands to install and configure the Ryu server:

```bash
# Switch to root user
sudo -s

# Install Git (if not already installed)
apt install git -y

# Clone the NetDefender repository
git clone https://github.com/sinyuan1022/NetDefender.git

# Navigate to the Ryu directory
cd ./NetDefender/ryu/

# Run the Ryu installation script
bash ./ryu_install.sh
```

---

### Snort Server Setup

After completing the Ryu server installation, proceed with the Snort server setup:

```bash
# Switch to root user
sudo -s

# Install Git (if not already installed)
apt install git -y

# Clone the NetDefender repository
git clone https://github.com/sinyuan1022/NetDefender.git

# Navigate to the Snort directory
cd ./NetDefender/snort/

# Run the Snort installation script
bash ./snort_install.sh
```

---

### Option 2: Single Server Deployment (Experimental)

> **⚠️ Note**: This option combines both Ryu and Snort servers on a single machine. This deployment mode is currently **not enabled** and should be used for testing purposes only.

```bash
# Switch to root user
sudo -s

# Install Git (if not already installed)
apt install git -y

# Clone the NetDefender repository
git clone https://github.com/sinyuan1022/NetDefender.git

# Navigate to the root directory
cd ./NetDefender/

# Run the combined installation script
bash ./singel.sh
```

---

## 🚀 Getting Started

1. **Prepare Your Environment**: Ensure both servers meet the system requirements listed above
2. **Configure Honeypots**: Edit the JSON configuration file to define your honeypot services
3. **Install Ryu Server**: Follow the Ryu server installation steps
4. **Install Snort Server**: Complete the Snort server setup on a separate machine (or the same machine for testing)
5. **Start Services**: Launch both Ryu and Snort services to begin monitoring and defense operations
6. **Monitor Traffic**: Observe network traffic redirection and honeypot interactions

---

## 📚 Additional Resources

- **Repository**: [github.com/sinyuan1022/NetDefender](https://github.com/sinyuan1022/NetDefender)
- **OSKen Controller**: Software-defined networking controller framework
- **Open vSwitch**: Production-quality multilayer virtual switch
- **Snort**: Open-source intrusion detection and prevention system
- **Cowrie**: SSH/Telnet honeypot designed to log brute force attacks

---

*This documentation provides a comprehensive guide to deploying NetDefender for network defense research and experimentation.*
