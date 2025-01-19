import subprocess
container_name = "ssh0"
subprocess.run(['docker', 'stop', container_name], check=True)
subprocess.run(['docker', 'rm', container_name], check=True)
