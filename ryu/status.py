import json
import time
import os
from tabulate import tabulate

JSON_FILE = "connect_status.json"


def format_ips_compact(ips):
    """簡化版：只顯示 IP 列表"""
    if not ips:
        return "-"
    return ", ".join(ip_info["ip"] for ip_info in ips[:5])


def format_ips_detail(ips):
    """詳細版：用於展開顯示"""
    if not ips:
        return "  No IPs"

    lines = []
    for i, ip_info in enumerate(ips, 1):
        ip_str = f"  {i}. {ip_info['ip']}"
        if "ports" in ip_info and ip_info["ports"]:
            ports_str = ", ".join(
                f'{p["protocol"]}:{p["src_port"]}->{p["dst_port"]}' for p in ip_info["ports"]
            )
            ip_str += f" [{ports_str}]"
        lines.append(ip_str)
    return "\n".join(lines)


try:
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')

        try:
            with open(JSON_FILE) as f:
                data = json.load(f)
        except FileNotFoundError:
            print("JSON file not found. Waiting for data...")
            time.sleep(1)
            continue

        # 主表格（簡化顯示）
        table = []
        for service_name, containers in data.items():
            for container_name, info in containers.items():
                table.append([
                    service_name,
                    container_name,
                    info["active_ips"],
                    format_ips_compact(info["ips"]),
                    "✓" if info["is_primary"] else "",
                    info["last_used"]
                ])

        print("=== Connection Status ===")
        print(tabulate(table, headers=["Service", "Container", "Active", "IPs (Top 5)", "Primary", "Last Used"]))

        # 詳細 IP 列表（折疊顯示）
        print("\n=== Detailed IP List ===")
        for service_name, containers in data.items():
            for container_name, info in containers.items():
                if info["ips"]:
                    print(f"\n[{service_name}] {container_name}:")
                    print(format_ips_detail(info["ips"]))

        print("\n" + "=" * 50)
        print("Refreshing in 10 seconds... (Press Ctrl+C to stop)")

        time.sleep(10)

except KeyboardInterrupt:
    print("\nStopped by user.")