if [ -z "$1" ]; then
    echo "請提供網路介面名稱，例如: bash ./start.sh ens33"
    exit 1
fi

INTERFACE=$1

if ! ip link show "$INTERFACE" &>/dev/null; then
    echo "網路介面 $INTERFACE 不存在"
    exit 1
fi

ovs-vsctl add-br br0

ifconfig $INTERFACE 0
ifconfig br0 0

ovs-vsctl add-port br0 $INTERFACE

dhclient br0

ovs-vsctl set-controller br0 tcp:127.0.0.1:6633
ifmetric br0 0
ifmetric ens33 0
ifmetric veth0 200
ifmetric veth1 200
ifmetric my-bridge 200
ovs-vsctl add-port br0 my-bridge

echo "設置完成，網路介面 $INTERFACE 已成功配置"
