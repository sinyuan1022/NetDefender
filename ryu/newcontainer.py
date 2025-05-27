import docker
def start_new_container(container_name, config):
    """創建新的容器"""
    client = docker.from_env()
    try:
        service_name = config['image_name']
        command = config.get('command')
        
        # 檢查容器是否已存在
        existing = client.containers.list(all=True, filters={"name": container_name})
        if existing:
            container = existing[0]
            # 如果容器存在但不在運行狀態，嘗試啟動它
            if container.status != "running":
                container.start()
                print(f"Started existing container {container_name}")
            else:
                print(f"Container {container_name} is already running")
            return True
        
        # 創建新容器
        container = client.containers.run(
            service_name,
            command=command if command else None,
            detach=True,
            network="my-dhcp-net",
            name=container_name
        )
        print(f"Created new container {container_name} from image {service_name}")
        return True
    except docker.errors.APIError as e:
        print(f"Error creating container {container_name}: {e}")
        return False

