#!/usr/bin/env python3
import subprocess
import sys
import time
import os


def run_cmd(cmd):
    """執行shell命令並返回輸出結果"""
    print(f"執行命令: {cmd}")
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"命令執行失敗")
        print(f"錯誤碼: {process.returncode}")
        print(f"錯誤輸出: {stderr}")
        print(f"標準輸出: {stdout}")
        raise Exception(f"命令執行失敗: {stderr}")
    return stdout


def create_container(container_name, image="ubuntu:20.04"):
    """創建容器並安裝必要的工具"""
    try:
        # 刪除舊容器
        try:
            run_cmd(f"docker rm -f {container_name}")
            print(f"已刪除舊的容器 {container_name}")
        except:
            pass

        # 創建新容器
        cmd = f"docker run -d --name {container_name}"
        cmd += " --network=none"
        cmd += " --privileged"
        cmd += " --cap-add=NET_ADMIN"
        cmd += " -v /var/run/docker.sock:/var/run/docker.sock"
        cmd += f" {image}"
        cmd += " /bin/bash -c '"
        # 安裝網絡工具
        cmd += "apt-get update && "
        cmd += "DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 iputils-ping net-tools && "
        cmd += "while true; do sleep 1000; done"
        cmd += "'"

        run_cmd(cmd)
        print(f"成功創建容器 {container_name} 並安裝網絡工具")
        return True

    except Exception as e:
        print(f"創建容器時發生錯誤: {str(e)}")
        return False


def setup_network(container_name, bridge_name="ovs-br0"):
    """設置容器網絡"""
    try:
        # 獲取容器PID
        pid = run_cmd(f"docker inspect -f '{{{{.State.Pid}}}}' {container_name}").strip()

        # 清理舊的網絡介面
        print("\n清理舊的網絡介面...")
        run_cmd("ip link delete veth0 2>/dev/null || true")
        run_cmd("ip link delete veth0_peer 2>/dev/null || true")

        # 創建新的veth pair
        print("\n創建新的veth pair...")
        run_cmd("ip link add veth0 type veth peer name veth0_peer")

        # 配置veth peer端
        print("\n配置veth peer端...")
        run_cmd("ip link set veth0_peer up")
        run_cmd("ip addr add 192.168.1.1/24 dev veth0_peer")

        # 將veth0移至容器namespace
        print("\n將veth0移至容器namespace...")
        run_cmd(f"ip link set veth0 netns {pid}")

        # 配置容器內部網絡
        print("\n配置容器內部網絡...")
        run_cmd(f"nsenter -t {pid} -n ip link set veth0 name eth0")
        run_cmd(f"nsenter -t {pid} -n ip addr add 192.168.1.2/24 dev eth0")
        run_cmd(f"nsenter -t {pid} -n ip link set eth0 up")
        run_cmd(f"nsenter -t {pid} -n ip link set lo up")

        # 配置OVS
        print("\n配置OVS橋接器...")
        run_cmd(f"ovs-vsctl --may-exist add-br {bridge_name}")
        run_cmd(f"ovs-vsctl --may-exist add-port {bridge_name} veth0_peer")
        run_cmd(f"ip link set {bridge_name} up")

    except Exception as e:
        print(f"設置網絡時發生錯誤: {str(e)}")
        raise


def verify_network(container_name):
    """驗證網絡設置"""
    print("\n驗證網絡設置:")
    try:
        # 檢查容器內網絡設置
        print("\n容器內網絡配置:")
        run_cmd(f"docker exec {container_name} ip addr show")

        # 檢查連接性
        print("\n測試網絡連接:")
        run_cmd(f"docker exec {container_name} ping -c 1 192.168.1.1")
        print("從主機 ping 容器:")
        run_cmd("ping -c 1 192.168.1.2")
    except Exception as e:
        print(f"網絡驗證失敗: {str(e)}")
        raise


def main():
    if os.geteuid() != 0:
        print("錯誤: 此腳本需要root權限運行")
        print("請使用: sudo python3 script.py ...")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("使用方式: sudo python3 script.py <container_name> [image_name] [bridge_name]")
        sys.exit(1)

    container_name = sys.argv[1]
    image_name = sys.argv[2] if len(sys.argv) > 2 else "ubuntu:20.04"
    bridge_name = sys.argv[3] if len(sys.argv) > 3 else "ovs-br0"

    try:
        print("創建容器並安裝網絡工具...")
        if create_container(container_name, image_name):
            print("等待容器啟動和工具安裝...")
            time.sleep(10)  # 給予足夠時間安裝工具

            print("設置網絡...")
            setup_network(container_name, bridge_name)

            print("驗證網絡設置...")
            verify_network(container_name)

            print(f"\n設置完成！")
            print(f"容器 IP: 192.168.1.2")
            print(f"veth peer IP: 192.168.1.1")
    except Exception as e:
        print(f"設置過程中發生錯誤: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
