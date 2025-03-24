# System environment
ryu server: Ubuntu22.04<br>
ryu Python:Python3.9<br>
snort server: Ubuntu22.04<br>
snort Python:Python3.9+

## !!! # is for comments

# Ryu server
first install ovs and docker
```
apt update
apt upgrade -y
apt install openvswitch-switch vim net-tools iptables-persistent dhcpcd5 htop ifmetric software-properties-common git screen dnsmasq -y
apt install docker.io=20.10.21-0ubuntu1~22.04.3 -y
add-apt-repository ppa:deadsnakes/ppa
apt update
git clone https://github.com/sinyuan1022/my-project.git
cd ./my-project/ryu/
apt install python3.9 python3.9-distutils -y
python3.9 get-pip.py
pip install setuptools==67.6.1 
pip install ryu docker scapy
pip install eventlet==0.30.2
docker plugin install ghcr.io/devplayer0/docker-net-dhcp:release-linux-amd64
python3.9 imagecheck.py
```
set Virtual NIC
```
ip link add veth0 type veth peer name veth1
ip addr add 192.168.100.1/24 dev veth0
ip link set veth0 up
ip link set veth1 up
ip link add my-bridge type bridge
ip link set my-bridge up
ip link set veth1 master my-bridge
iptables -A FORWARD -i my-bridge -j ACCEPT
iptables -I FORWARD -o my-bridge -j ACCEPT
```
![image](https://github.com/user-attachments/assets/d1e1fc1f-f132-4634-a8de-80ba7a50c77d)
enabling IPv4 Packet Forwarding
```
vim /etc/sysctl.conf

net.ipv4.ip_forward = 1 #updata
```
![image](https://github.com/user-attachments/assets/1bef166b-2144-455b-9dbe-1c02ca343fe1)

apply changes
```
sysctl -p
iptables -P FORWARD ACCEPT
```
set dhcp-server 
```
vim /etc/dnsmasq.conf
```
```
port=0
interface=veth0 #veth0 is your dhcp NIC name
no-dhcp-interface=br0
listen-address=192.168.100.1 
listen-address=127.0.0.1
dhcp-range=192.168.100.2,192.168.100.254,255.255.255.0,1h
dhcp-option=3,192.168.100.1
dhcp-option=28,192.168.100.255
dhcp-option=6,8.8.8.8,8.8.4.4
```
![image](https://github.com/user-attachments/assets/e7567b8d-26da-4dfe-80b6-f2b73de6cbf6)

set ovs(dhcp interface)
Please change it to the local network adapter
ens33 is used on br0
```
ovs-vsctl add-port br0 ens33
ovs-vsctl set-controller br0 tcp:127.0.0.1:6633
ifconfig ens33 0
dhclient br0
```
set ovs(static ip)
Please change it to the local network adapter
ens33 is used on br0
ens34 is used for remote connections (if remote connection is not needed, it can be left unconfigured)
```
vim /etc/netplan/*.yaml
```
```
network:
  version: 2
  renderer: networkd
  ethernets:
    ens33: 
      dhcp4: no
    ens34:
      addresses:
        - 192.168.1.104/24
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
      routes:
        - to:  192.168.1.0/16
          via: 192.168.1.1
  bridges:
    br0:
      interfaces: [ens33]
      addresses:
        - 192.168.254.137/24
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
      routes:
        - to: default
          via: 192.168.254.2
      parameters:
        stp: false
        forward-delay: 0
      openvswitch:
        fail-mode: standalone
        controller:  
          addresses:
            - tcp:127.0.0.1:6653

```
![image](https://github.com/user-attachments/assets/89a2e888-3e52-4c3d-8856-e96c3fb7f9fc)
![image](https://github.com/user-attachments/assets/27c52736-fb59-4a13-9d28-5e1c6ed15f26)
```
chmod 600 /etc/netplan/*yaml
netplan try
systemctl restart systemd-networkd
netplan apply
netplan apply
```
![image](https://github.com/user-attachments/assets/8e9c1196-40c8-4270-8c4d-c05b79795133)

get ip
```
systemctl restart dnsmasq
dhclient veth1
dhcpcd my-bridge
```
![image](https://github.com/user-attachments/assets/d819c9e5-18aa-4682-907d-b07e71399d83)

set docker network
```
docker network create -d ghcr.io/devplayer0/docker-net-dhcp:release-linux-amd64 --ipam-driver null -o bridge=my-bridge my-dhcp-net
```
![image](https://github.com/user-attachments/assets/6f8219ce-0ae2-49d9-8215-45d0c5bbfa32)

Run Ryu
Then, start pigrelay inside the Snort server.
```
ryu-manager ovs.py   #it is not run in background

screen -dmS ryu ryu-manager ovs.py   #it is run in background
```
![image](https://github.com/user-attachments/assets/6ba3fbfc-9512-4ca4-aeab-e42a8f382369)
---
# Snort server
install snort and python
```
apt update
apt upgrade -y
apt install python3 python3-pip snort git vim net-tools -y
git clone https://github.com/sinyuan1022/my-project.git
cd ./my-project/snort

ifconfig ens33 promisc   #ens33 is your snort server NIC name
```
run snort 
```
# ens33 is your snort server NIC name
snort -i ens33 -A unsock -l /tmp -c /etc/snort/snort.conf   #it is not run in background

screen -dmS snort snort -i ens33 -A unsock -l /tmp -c /etc/snort/snort.conf   #it is run in background
```
![image](https://github.com/user-attachments/assets/d66c5c91-3d5f-451b-8e20-b5001f07afa0)

set controller IP(run to background)
```
vim ./settings.py

CONTROLLER_IP = '192.168.2.179'   #change ryu server IP
```
![image](https://github.com/user-attachments/assets/ffab87d9-36d9-4c8e-b589-58f80d045731)

set controller IP(not background)
```
vim ./pigrelay.py

CONTROLLER_IP = '127.0.0.1'   #change ryu server IP
```
![image](https://github.com/user-attachments/assets/3ce5243b-ca75-40a7-aeb9-2d1aa68cf4ee)

run pigrelay
Start ryu first, then start pigrelay
```
python3 pigrelay.py   #it is not run in background

python3 hpigrelay.py start   #it is run in background
```
![image](https://github.com/user-attachments/assets/5c1b3cd2-3a0e-40ed-a944-7626fb6b2dad)

