import docker
def start_new_container(container_name, config):
    client = docker.from_env()
    service_name = config['image_name']
    command = config['command']
    client.containers.run(
        service_name,
        command=command if command else None,
        detach=True,
        network="my-dhcp-net",
        name=container_name
    )