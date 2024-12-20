import json

def config():
    try:
        # 读取配置文件
        with open('config.json', 'r') as f:
            config = json.load(f)

        # 构建端口到详细容器信息的映射
        port_to_container = {
            container['port']: {
                'image_name': container['image_name'],
                'target_port': container['target_port']
            }
            for container in config.get('containers', [])
            if 'port' in container and 'image_name' in container
        }

        return port_to_container

    except FileNotFoundError:
        print("Error: Configuration file 'config.json' not found.")
        return {}
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'config.json'.")
        return {}
