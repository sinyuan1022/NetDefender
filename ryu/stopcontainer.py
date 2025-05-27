
import docker

def stop_container(container_name, container_status):
    """停止並移除容器，但保留主要容器和備用容器"""
    client = docker.from_env()
    try:
        # 解析服務名稱（假設格式為 "service_name0", "service_name1" 等）
        service_name = None
        for name in container_name.split('_')[:-1]:
            if not service_name:
                service_name = name
            else:
                service_name += "_" + name
        
        # 檢查容器狀態
        if service_name in container_status and container_name in container_status[service_name]:
            # 主要容器和備用容器不應該被停止
            if container_status[service_name][container_name].get("is_primary", False):
                print(f"Skipping stop request for primary container {container_name}")
                return False
                
            if container_status[service_name][container_name].get("is_spare", False):
                print(f"Skipping stop request for spare container {container_name}")
                return False
        
        # 停止並移除容器
        container = client.containers.get(container_name)
        container.stop()
        container.remove()
        print(f"Successfully stopped and removed container {container_name}")
        return True
    except docker.errors.NotFound:
        print(f"Container {container_name} does not exist")
        return False
    except docker.errors.APIError as e:
        print(f"Error stopping container {container_name}: {e}")
        return False

