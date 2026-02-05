# NetDefender

# System environment
Ryu Server: Ubuntu22.04<br>
Ryu Python: Python3.9<br>
Snort Server: Ubuntu22.04<br>
Snort Python: Python3.9+
# Attention
  #is for comments
  
  Ryu server must be completed first
  
  Please connect to the internet before installing the two servers
  
  
# network environment
<img width="1019" height="637" alt="image" src="https://github.com/user-attachments/assets/3c2be482-1a8f-49ce-82ce-e933007d856f" />

# config honeypot
```Python
{
  "containers": [
    {
      "port": 22, #Packet enters the port
      "image_name": "cowrie/cowrie", #Docker Image Name
      "name": "ssh", #The container name can be any valid string
      "target_port": 2222, #The container's egress port
      "command": "", #Docker command arguments
      "multi": "yes", #Whether to spawn multiple containers
      "max": 10, #Maximum concurrent connections
      "max_containers":10, #Maximum number of containers allowed
      "send_response":"yes" # Whether to return packets
    },{
      #other honeypot
    }
  ]
}
```
# Ryu server
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/ryu/

bash ./ryu_install.sh
```
# Snort server
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/snort/

bash ./snort_install.sh
```
## Single server combines the Ryu server and the Snort server into a single server
# singel server(Not enabled)
```bash
sudo -s

apt install git -y
git clone https://github.com/sinyuan1022/NetDefender.git
cd ./NetDefender/

bash ./singel.sh
```
