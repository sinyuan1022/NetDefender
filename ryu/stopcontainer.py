import docker

def stop_container(self, container_name, container_status):
    """停止並移除指定容器"""
    client = docker.from_env()
    
    try:
        # 解析服務名
        service_name = container_name.rsplit('_', 1)[0] if '_' in container_name else container_name
        
        # 檢查容器是否是主容器
        if (service_name in container_status and 
            container_name in container_status[service_name] and
            container_status[service_name][container_name].get("is_primary", False)):
            self.logger.info(f"Skipping stop request for primary container {container_name}")
            return
        
        # 獲取容器並停止/移除
        container = client.containers.get(container_name)
        container.stop()
        container.remove()
        
        # 從狀態中移除容器記錄
        if service_name in container_status and container_name in container_status[service_name]:
            del container_status[service_name][container_name]
            
        self.logger.info(f"Successfully stopped and removed container {container_name}")
    except docker.errors.NotFound:
        print(f"Container {container_name} does not exist")
    except docker.errors.APIError as e:
        print(f"Error deleting container: {e}")
    except Exception as e:
        print(f"Unknown error occurred: {e}")
