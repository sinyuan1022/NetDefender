#!/usr/bin/python
"""
This is the most simple example to showcase Containernet.
"""
from mininet.net import Containernet
from mininet.node import Controller, RemoteController, OVSSwitch, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.link import Intf
from mininet.topo import LinearTopo
from mininet.topo import Topo as topo
from functools import partial

setLogLevel('info')

net = Containernet(controller=None)
info('*** Adding controller\n')
# net.addController('c0')
info('*** Adding docker containers\n')

# d1 = net.addDocker('h1',
#                   ip='10.0.0.251',
#                   dcmd='/entrypoint.sh',
#                   ports=[10000, 80, 3000, 8089],
#                   port_bindings={10000: 10000,
#                                  80: 80,
#                                  3000: 3000,
#                                  8089: 8089},
#                    environment={"SUPERUSER_EMAIL": "root@localhost",
#                                 "SUPERUSER_PASSWORD": "password",
#                                 "SERVER_BASE_URL": "http://localhost",
#                                 "HONEYMAP_URL": "http://localhost:3000"},
#                    dimage="mhn")

# d1 = net.addDocker('h1',
#                    ip='10.0.0.251',
#                    dcmd='/usr/local/sbin/entrypoint.sh',
#                    ports=[21, 42, 69, 80, 135, 443, 445, 1433, 1723, 1883, 1900, 3306, 5060, 5061],
#                    port_bindings={21: 21,
#                                   42: 42,
#                                   69: 69,
#                                   80: 80,
#                                   135:135,
#                                   443:443,
#                                   445:445,
#                                   1433:1433,
#                                   1723:1723,
#                                   1883:1883,
#                                   1900:1900,
#                                   3306:3306,
#                                   5060:5060,
#                                   5061:5061
#                             },

#                     dimage="dionaea")

br1 = net.addSwitch('br1', cls=OVSKernelSwitch)
d2 = net.addDocker('h2', dimage="ubuntu",ports=[2222],port_bindings={2222:2222})

#d3 = net.addDocker('h3', ip='192.168.10.3', dimage="ubuntu")


# 添加 Docker 容器，並設置 IP 地址

# 將 Docker 容器連接到現有的 OVS 桥接
net.addLink(d2, br1)
info('*** Adding switches\n')
#s1 = net.addSwitch('s1', protocols="OpenFlow13")
#Intf('br0', node=s1)
# s2 = net.addSwitch('s2')
info('*** Creating links\n')
# net.addLink(s1, d1)
# net.addLink(d1, s1)
# net.addLink(s1, s2, cls=TCLink, delay='100ms', bw=1)
net.addLink(d2,'br0')
#net.addLink(s1, d2)
#net.addLink(s1, d3)

info('*** Starting network\n')
net.start()
info('*** Testing connectivity\n')
#net.ping([d2, d3])
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()

# docker run -d -p 10000:10000 -p 80:80 -p 3000:3000 -p 8089:8089 --restart unless-stopped --name mhn
# -e SUPERUSER_EMAIL=root@localhost
# -e SUPERUSER_PASSWORD=password
# -e SERVER_BASE_URL="http://localhost"
# -e HONEYMAP_URL="http://localhost:3000" mhn_build_22.04:latest


# ryu-manager --observe-links ryu/ryu/app/gui_topology/gui_topology.py ryu/ryu/app/simple_switch_13.py
# sudo mn --controller remote,ip=127.0.0.1 --topo linear,20 --mac --switch ovsk --link tc
