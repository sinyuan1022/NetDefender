import docker
import subprocess
import time



def start_container(image_name,sip,allip):
    client = docker.from_env()
    try:
        client.ping()
        print("Docker is running.")
    except docker.errors.DockerException:
        print("Docker is not running. Please start the Docker service.")
        return
    try:
        container = client.containers.get(ip)
        print(f"Container '{container.name}' started with ID: {container.id}")
        container.reload()
        ip_address = container.attrs['NetworkSettings']['IPAddress']
        print(f"Container IP Address: {ip_address}")
        return ip_address
    except docker.errors.NotFound:
        container = client.containers.run(image_name,name=ip,network="none",tty=True,detach=True)
        print(f"Container '{container.name}' started with ID: {container.id}")
        container.reload()
        ip_address = container.attrs['NetworkSettings']['IPAddress']
        print(f"Container IP Address: {ip_address}")
        return ip_address
    except docker.errors.APIError as e:
        print(f"Failed to start container: {e}")