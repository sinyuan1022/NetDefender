import docker
def stop_container(self, container_name,container_status):
    client = docker.from_env()
    try:
        service_name = container_name.rsplit('_', 1)[0]
        if container_name in container_status[service_name]:
            if container_status[service_name][container_name].get("is_primary", False):
                self.logger.info(f"Skipping stop request for primary container {container_name}")
                return

        container = client.containers.get(container_name)
        container.stop()
        container.remove()
        self.logger.info(f"Successfully stopped and removed container {container_name}")
    except docker.errors.NotFound:
        print(f"容器 {container_name} 不存在。")
    except docker.errors.APIError as e:
        print(f"刪除容器時出錯: {e}")