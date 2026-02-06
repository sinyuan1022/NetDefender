import docker

def start_new_container(container_name, config):
    """啟動新的容器"""
    try:
        client = docker.from_env()
        service_name = config['image_name']
        command = config.get('command', '')
        
        # 檢查同名容器是否已存在
        existing_containers = client.containers.list(all=True, filters={"name": container_name})
        if existing_containers:
            # 如果存在但未運行，則嘗試啟動
            for container in existing_containers:
                if container.status != "running":
                    container.start()
                return True
        
        # 創建並啟動新容器
        container = client.containers.run(
            service_name,
            command=command if command else None,
            detach=True,
            network="my-dhcp-net",
            name=container_name
        )
        
        print(f"Successfully created and started container {container_name}")
        return True
    except docker.errors.ImageNotFound:
        print(f"Image {config['image_name']} does not exist")
        return False
    except docker.errors.APIError as e:
        print(f"Error starting container: {e}")
        return False
    except Exception as e:
        print(f"Unknown error occurred: {e}")
        return False
