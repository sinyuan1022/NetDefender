import docker
import logging

logger = logging.getLogger(__name__)

def getcontainer_ip(container_name):
    """
    取得容器的 IP 位址。
    成功回傳 IP 字串；失敗回傳 None。
    """
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)

        if container.status != 'running':
            logger.warning(f"容器 {container_name} 狀態為 {container.status}，非 running，無法取得 IP")
            return None

        network_settings = container.attrs['NetworkSettings']

        ip_address = network_settings.get('IPAddress', '')
        if ip_address:
            return ip_address

        networks = network_settings.get('Networks', {})
        for network_name, config in networks.items():
            ip = config.get('IPAddress', '')
            if ip:
                logger.debug(f"從網路 {network_name} 取得 IP: {ip}")
                return ip

        logger.error(f"容器 {container_name} 找不到任何有效 IP，NetworkSettings: {network_settings}")
        return None

    except docker.errors.NotFound:
        logger.error(f"容器 {container_name} 不存在")
        return None
    except docker.errors.APIError as e:
        logger.error(f"Docker API 錯誤: {e}")
        return None
    except Exception as e:
        logger.error(f"取得容器 IP 時發生未預期錯誤: {e}")
        return None
