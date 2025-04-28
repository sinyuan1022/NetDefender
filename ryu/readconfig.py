import json


def config():
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)


        port_to_container = {}
        for container in config.get('containers', []):
            if 'port' in container and 'image_name' in container:
                port = container['port']
                container_info = {
                    'image_name': container['image_name'],
                    'target_port': container['target_port'],
                    'name': container['name'],
                    'command': container['command'],
                    'multi': container['multi'],
                    'max': container.get('max', 1) 
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
