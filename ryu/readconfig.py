import json

def config():
    """讀取配置文件"""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
        port_to_container = {}
        monitor_port = []
        return_port = []
        for container in config.get('containers', []):
            if 'port' in container and 'image_name' in container:
                port = container['port']
                container_info = {
                    'image_name': container['image_name'],
                    'target_port': container.get('target_port', port),
                    'name': container.get('name', f'service_{port}'),
                    'command': container.get('command', ''),
                    'multi': container.get('multi', 'no'),
                    'max': int(container.get('max', 10)),
                    'max_containers':int(container.get('max_containers', 10)),
                    "send_response": container.get('send_response', 'no')
                }
                if port not in port_to_container:
                    port_to_container[port] = []
                if container['send_response'] == "yes":
                    monitor_port.append(port)
                    return_port.append(container['target_port'])

                port_to_container[port].append(container_info)

        return port_to_container,monitor_port,return_port
    except FileNotFoundError:
        print("Error: Configuration file 'config.json' not found.")
        return {},[],[]
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'config.json'.")
        return {},[],[]
    except Exception as e:
        print(f"Error reading configuration: {e}")
        return {},[],[]
