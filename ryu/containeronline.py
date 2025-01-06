import os
import docker
os.system(f"ip link delete {veth_host} type veth 2>/dev/null || true")
os.system(f"ip link delete {veth_container} type veth 2>/dev/null || true")
