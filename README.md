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
enabling IPv4 Packet Forwarding
```
vim /etc/sysctl.conf
net.ipv4.ip_forward = 1 #updata
```
apply changes
```
sysctl -p
iptables -P FORWARD ACCEPT
```
set dhcp-server 
```
vim /etc/dnsmasq.conf
interface=veth0 #veth0 is your dhcp NIC name
except-interface=*
bind-interfaces
dhcp-range=192.168.100.2,192.168.100.254,255.255.255.0,1h
```
set ovs
```
bash ./setovs.sh ens33  #ens33 is your ryu server NIC name
```
get ip
```
systemctl restart dnsmasq
dhclient veth1
dhclient my-bridge
```
set docker network
```
docker network create -d ghcr.io/devplayer0/docker-net-dhcp:release-linux-amd64 --ipam-driver null -o bridge=my-bridge my-dhcp-net
```
Run Ryu
```
ryu-manager ovs.py   #it is not run in background

screen -dmS ryu ryu-manager ovs.py   #it is run in background
```
run container(Later, change it to automation.)
```
#Use two terminals to run
docker run --rm -ti --name ssh0 --network my-dhcp-net cowrie/cowrie
```
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
set controller IP(run to background)
```
vim ./settings.py

CONTROLLER_IP = '192.168.2.179'   #change ryu server IP
```

set controller IP(not background)
```
vim ./pigrelay.py

CONTROLLER_IP = '127.0.0.1'   #change ryu server IP
```
run pigrelay
```
python3 pigrelay.py   #it is not run in background

python3 hpigrelay.py start   #it is run in background
```

