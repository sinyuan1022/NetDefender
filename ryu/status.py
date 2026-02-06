import json
import time
import os
from tabulate import tabulate

JSON_FILE = "connect_status.json"
try:
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        # 讀取 JSON
        try:
            with open(JSON_FILE) as f:
                data = json.load(f)
        except FileNotFoundError:
            print("JSON file not found. Waiting for data...")
            time.sleep(1)
            continue

        # 組表格
        table = []
        for service_name, containers in data.items():
            for container_name, info in containers.items():
                table.append([
                    service_name,
                    container_name,
                    info["active_ips"],
                    ", ".join(info["ips"]),
                    info["is_primary"],
                    info["last_used"]
                ])

        # 顯示表格
        print(tabulate(table, headers=["Service", "Container", "Active IPs", "IPs", "Primary", "last_used"]))
        # 每秒刷新一次
        time.sleep(10)

except KeyboardInterrupt:
    print("\nStopped by user.")
