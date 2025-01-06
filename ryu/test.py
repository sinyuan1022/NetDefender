import docker

# 创建 Docker 客户端
client = docker.from_env()

# 指定容器名称或 ID
container_name = "ssh1"

try:
    # 获取容器对象
    container = client.containers.get(container_name)

    # 获取网络信息
    network_settings = container.attrs['NetworkSettings']

    # 获取默认网络中的 IP 地址
    ip_address = network_settings['IPAddress']
    print(f"Container '{container_name}' IP address: {ip_address}")

    # 如果有多个网络
    networks = network_settings['Networks']
    for network_name, config in networks.items():
        print(f"Network '{network_name}': IP {config['IPAddress']}")

except docker.errors.NotFound:
    print(f"Container '{container_name}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")
