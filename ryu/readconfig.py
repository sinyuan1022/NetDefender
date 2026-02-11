import json

def config():
    """讀取配置文件，支援單個 port 或多個 ports"""
    try:
        with open('config.json', 'r') as f:
            config = json.load(f)

        port_to_container = {}
        tcp_monitor_port = []
        udp_monitor_port = []
        tcp_return_port = []
        udp_return_port = []
        for container in config.get('containers', []):
            if 'image_name' not in container:
                continue

            # 收集所有需要映射的端口
            port_mappings = []

            if 'ports' in container:
                for port_map in container['ports']:
                    port_mappings.append({
                        'host': port_map['host_port'],
                        'container': port_map.get('container_port', port_map['host_port']),
                        'protocol': port_map.get('protocol', 'tcp')
                    })
            # 為每個端口創建容器配置
            for pm in port_mappings:
                container_info = {
                    'image_name': container['image_name'],
                    'target_port': pm['container'],
                    'protocol': pm['protocol'],
                    'name': container.get('name', f"service_{pm['host']}"),
                    'command': container.get('command', ''),
                    'multi': container.get('multi', 'no'),
                    'max': int(container.get('max', 10)),
                    'max_containers': int(container.get('max_containers', 10)),
                    'send_response': container.get('send_response', 'no')
                }

                host_port = pm['host']
                if host_port not in port_to_container:
                    port_to_container[host_port] = []
                port_to_container[host_port].append(container_info)

                if container_info['send_response'] == 'yes':
                    if container_info['protocol'] == 'tcp':
                        if host_port not in tcp_monitor_port:
                            tcp_monitor_port.append(host_port)
                        if pm['container'] not in tcp_return_port:
                            tcp_return_port.append(pm['container'])
                    elif container_info['protocol'] == 'udp':
                        if host_port not in udp_monitor_port:
                            udp_monitor_port.append(host_port)
                        if pm['container'] not in udp_return_port:
                            udp_return_port.append(pm['container'])

        return port_to_container, tcp_monitor_port, tcp_return_port,udp_monitor_port,udp_return_port

    except FileNotFoundError:
        print("Error: Configuration file 'config.json' not found.")
        return {}, [], []
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'config.json'.")
        return {}, [], []
    except Exception as e:
        print(f"Error reading configuration: {e}")
        return {}, [], []