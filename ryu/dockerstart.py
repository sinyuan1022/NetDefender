import docker
import json


def start_containers(config):
    client = docker.from_env()
    containers = config.get("containers", [])

    for container in containers:
        image_name = container.get("image_name")
        command = container.get("command", "")
        name = container.get("name")

        existing_containers = client.containers.list(filters={"name": name}) if name else []
        if existing_containers:
            print(f"Container {name} is already running.")
            continue

        print(f"Starting container {container.get('image_name')}...")

        client.containers.run(
            image_name,
            command=command if command else None,
            detach=True,
            network="my-dhcp-net",
            name= f"{name}0"
        )
    print("All containers started.")

def start():
    with open('config.json', 'r') as f:
        config = json.load(f)
        start_containers(config)
