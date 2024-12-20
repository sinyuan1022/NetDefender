import docker 

def getcontainer_ip(container_name):
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        network_settings = container.attrs['NetworkSettings']
        ip_address = network_settings['IPAddress']
        if ip_address:
            return ip_address
        networks = network_settings['Networks']
        for network_name, config in networks.items():
            return config['IPAddress']

    except docker.errors.NotFound:
        return 0
    except Exception as e:
        return -1