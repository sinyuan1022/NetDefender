ovs-vsctl add-br br0
ifconfig ens33 0
ifconfig br0 0
ovs-vsctl add-port br0 ens33
dhclient br0
ovs-vsctl set-controller br0 tcp:127.0.0.1:6633
