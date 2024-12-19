import os
import docker

# 初始化 Docker 客户端
client = docker.from_env()

# ---- Step 1: 启动容器 ----
container_name = "owo"
image_name = "ubuntu"  # 使用任意你需要的容器镜像

# 创建容器，禁用默认网络（使用 network_mode="none"）
container = client.containers.run(
        image_name,
        detach=True,
        stdin_open=True,
        tty=True,
        name=container_name,
        network_mode="none"
    )

print(f"启动容器: {container.name}，ID: {container.id}")

import time

# 等待容器启动完成并获取 PID
retries = 10
while retries > 0:
    container.reload()
    container_pid = container.attrs['State']['Pid']
    if container_pid != 0:  # PID 已经获取成功
        break
    retries -= 1
    time.sleep(1)

if container_pid == 0:
    raise RuntimeError("无法获取容器 PID，请检查容器是否正常启动")

print(f"{container_name} 的 PID: {container_pid}")

# ---- Step 2: 创建 veth pair ----
veth_host = "veth_host"
veth_container = "veth_container"
os.system(f"ip link delete {veth_host} type veth 2>/dev/null || true")
os.system(f"ip link delete {veth_container} type veth 2>/dev/null || true")

print("创建虚拟网卡对 (veth pair)...")
os.system(f"ip link add {veth_host} type veth peer name {veth_container}")

# ---- Step 3: 将宿主机端的 veth 绑定到 OVS ----
ovs_bridge = "br0"

# 确保 OVS bridge 存在
os.system(f"ovs-vsctl add-br {ovs_bridge}")
print(f"已创建 OVS 桥接: {ovs_bridge}")

# 将 veth_host 端连接到 OVS 桥接
os.system(f"ovs-vsctl --if-exists del-port {ovs_bridge} {veth_host}")
# 添加新的端口
os.system(f"ovs-vsctl add-port {ovs_bridge} {veth_host}")
print(f"veth_host 接口已被连接到 OVS 桥接 {ovs_bridge}")

# 将宿主机的虚拟网卡设置为 up
os.system(f"ip link set {veth_host} up")

# ---- Step 4: 将 veth_container 端移动到容器命名空间 ----
print(f"将 {veth_container} 移动到容器 {container_name} 的命名空间...")
os.system(f"ip link set {veth_container} netns {container_pid}")

# ---- Step 5: 配置容器虚拟网卡 ----
container_ip = "192.168.1.101"
container_subnet = "192.168.1.0/24"
gateway_ip = "192.168.1.1"

# 配置容器内部网卡名称并启用
os.system(f"nsenter -t {container_pid} -n ip addr add {container_ip}/24 dev {veth_container}")
os.system(f"nsenter -t {container_pid} -n ip link set {veth_container} up")

# 配置默认路由
os.system(f"nsenter -t {container_pid} -n ip route add default via {gateway_ip}")
print(f"容器内 veth 配置完成, IP 地址: {container_ip}, 默认网关: {gateway_ip}")

print("网络配置完成！")

# ---- 测试: 展示当前 OVS 配置 ----
os.system("ovs-vsctl show")
