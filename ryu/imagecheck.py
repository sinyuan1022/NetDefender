import json
import docker
with open('config.json', 'r') as f:
    client = docker.from_env()
    config = json.load(f)
    containers = config.get("containers", [])
    for container in containers:
        image_name = container.get("image_name")
        try:
            client.images.get(image_name)
            print(f"Image {image_name} already exists.")
        except docker.errors.ImageNotFound:
            print(f"Image {image_name} not found. Pulling...")
            client.images.pull(image_name)
