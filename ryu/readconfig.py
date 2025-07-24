import json

def config():
    """讀取配置文件"""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)
            
        port_to_container = {}
        
        for container in config.get('containers', []):
            if 'port' in container and 'image_name' in container:
                port = container['port']
                
                container_info = {
                    'image_name': container['image_name'],
                    'target_port': container.get('target_port', port),
                    'name': container.get('name', f'service_{port}'),
                    'command': container.get('command', ''),
                    'multi': container.get('multi', 'no'),
                    'max': int(container.get('max', 1)),
                    'max_containers':int(container.get('max_containers', 1))
                }
                
                if port not in port_to_container:
                    port_to_container[port] = []
                    
                port_to_container[port].append(container_info)
                
        return port_to_container
    except FileNotFoundError:
        print("Error: Configuration file 'config.json' not found.")
        return {}
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'config.json'.")
        return {}
    except Exception as e:
        print(f"Error reading configuration: {e}")
        return {}
