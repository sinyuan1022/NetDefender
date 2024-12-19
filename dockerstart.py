import docker
import subprocess
import random
import time

def random_ip(allip):
    ips=set()
    ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    if ip in allip:
        random_ip(allip)
    return ip


def start_container(image_name,sip,allip):
    client = docker.from_env()
    try:
        client.ping()
        print("Docker is running.")
    except docker.errors.DockerException:
        print("Docker is not running. Please start the Docker service.")
        return
    
    if allip.get(sip):
        return allip.get(sip)
    else:
        container = client.containers.run(image_name,name=sip,network="none",tty=True,detach=True)
        ip=random_ip(allip)
        time.sleep(10)
        cmd = ['ovs-docker', 'add-port' ,'br0', 'eth0' ,f'{sip}' ,f'--ipaddress={ip}/24']
        re=subprocess.run(cmd,capture_output=True,check=True,text=True)
        #container.reload()
        return ip

    '''
    try:
        container = client.containers.get(ip)
        print(f"Container '{container.name}' started with ID: {container.id}")
        container.reload()
        ip_address = container.attrs['NetworkSettings']['IPAddress']
        print(f"Container IP Address: {ip_address}")
        return container.id,ip_address
    except docker.errors.NotFound:
        container = client.containers.run(image_name,name=ip,network="none",tty=True,detach=True)
        print(f"Container '{container.name}' started with ID: {container.id}")
        container.reload()
        ip_address = container.attrs['NetworkSettings']['IPAddress']
        print(f"Container IP Address: {ip_address}")
        return container.id,ip_address
    except docker.errors.APIError as e:
        print(f"Failed to start container: {e}")'''