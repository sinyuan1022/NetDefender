import json

def config():
    with open('config.json', 'r') as f:
        config = json.load(f)
    return{container['port']: container['image_name'] for container in config['containers']}