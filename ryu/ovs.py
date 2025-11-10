from __future__ import print_function
import array
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import icmp
import snortlib
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from os_ken.ofproto import ether, inet
from os_ken.lib import hub
from datetime import datetime
import hashlib
import subprocess
import re
import readconfig as rc
import dockerstart
import getip
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.utils import wrpcap
from newcontainer import start_new_container
from stopcontainer import stop_container
import os
import docker
import math

class SimpleSwitchSnort(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = 3
        self.mac_to_port = {}
        self.connection_map = {}
        self.connection_ip = {}
        socket_config = {'unixsock': False}
        self.dockerid = {}
        self.docker_config = rc.config()
        self.packet_store = []
        self.monitor_thread = hub.spawn(self._monitor)
        self.localIP = self.get_ip_address('br0')
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        self.dockerstart = dockerstart.start()
        self.docker_client = docker.from_env()
        self.container_monitor = hub.spawn(self._container_monitor)
        # Track last connection time for each IP by service
        self.ip_connection_times = {}
        # Map of IP to container for each service
        self.ip_container_map = {}
        # Define how long an IP connection is considered "active" (seconds)
        self.IP_CONNECTION_TIMEOUT = 300  # 5 minutes
        # Count of unique active IPs per service
        self.service_active_ip_count = {}
        # 容器狀態管理
        # {service_name: {container_name: {"last_used": timestamp, "ip": client_ip, "is_primary": bool, "config": config, "active_connections": int}}}
        self.container_status = {}

        # IP到容器的映射
        # {service_name: {client_ip: container_name}}
        self.ip_container_map = {}

        # 定義容器超時時間(秒)
        self.CONTAINER_TIMEOUT = 300  # 5分鐘

        # 初始化所有服務
        self.initialize_services()

    def initialize_services(self):
        """初始化所有服務的容器管理"""
        for port, configs in self.docker_config.items():
            if not configs:
                continue

            service_name = configs[0].get('name', f'service_{port}')
            self.container_status[service_name] = {}
            self.ip_container_map[service_name] = {}

            # 檢查主容器是否已經運行
            container_name = f"{service_name}0"

            try:
                existing_containers = self.docker_client.containers.list(filters={"name": container_name})

                if existing_containers:
                    # 如果容器已存在，更新狀態
                    self.container_status[service_name][container_name] = {
                        "last_used": datetime.now(),
                        "ip": None,
                        "is_primary": True,
                        "config": configs[0],
                        "active_connections": 0
                    }
                    self.logger.info(f"Found existing container: {container_name}")
                else:
                    # 如果容器不存在，創建主容器
                    self.logger.info(f"Creating primary container for service: {service_name}")
                    if start_new_container(container_name, configs[0]):
                        self.container_status[service_name][container_name] = {
                            "last_used": datetime.now(),
                            "ip": None,
                            "is_primary": True,
                            "config": configs[0],
                            "active_connections": 0
                        }

                # 對於支持多開的服務，預先創建一個備用容器
                if configs[0].get('multi', 'no') == 'yes':
                    reserve_container_name = f"{service_name}1"

                    try:
                        reserve_containers = self.docker_client.containers.list(filters={"name": reserve_container_name})

                        if not reserve_containers:
                            self.logger.info(f"Creating reserve container: {reserve_container_name}")
                            if start_new_container(reserve_container_name, configs[0]):
                                self.container_status[service_name][reserve_container_name] = {
                                    "last_used": datetime.now(),
                                    "ip": None,
                                    "is_primary": False,
                                    "config": configs[0],
                                    "active_connections": 0
                                }
                        else:
                            self.container_status[service_name][reserve_container_name] = {
                                "last_used": datetime.now(),
                                "ip": None,
                                "is_primary": False,
                                "config": configs[0],
                                "active_connections": 0
                            }
                    except Exception as e:
                        self.logger.error(f"Error creating reserve container: {e}")

            except Exception as e:
                self.logger.error(f"Error initializing service {service_name}: {e}")

    def get_ip_address(self, interface_name):
        try:
            result = subprocess.run(['ip', 'addr', 'show', interface_name], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  text=True)

            if result.returncode != 0:
                print(f"Error: {result.stderr.strip()}")
                return None

            match = re.search(r'inet\s+([\d.]+)', result.stdout)
            if match:
                print(f"local ip:{match.group(1)}")
                return match.group(1)
            else:
                print("No IP address found.")
                return None
        except Exception as e:
            print(f"Error: {e}")
            return None

    def _monitor(self):
        """監控封包處理"""
        while True:
            # 處理安全封包 (超過3秒沒有收到警告的封包)
            while self.packet_store and (datetime.now() - self.packet_store[0][2]).total_seconds() > 3:
                pkt_hash, msg, timestamp = self.packet_store.pop(0)
                datapath = msg.datapath
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                in_port = msg.match['in_port']

                pkt = packet.Packet(msg.data)
                eth = pkt.get_protocols(ethernet.ethernet)[0]
                dst = eth.dst
                src = eth.src
                dpid = datapath.id

                # 更新MAC地址表
                self.mac_to_port.setdefault(dpid, {})
                self.mac_to_port[dpid][src] = in_port

                # 查找輸出端口
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD

                # 準備流表動作
                actions = [parser.OFPActionOutput(out_port)]

                # 如果輸出端口已知，添加流表
                if out_port == ofproto.OFPP_LOCAL:
                    # 只發一次性 PacketOut，不安裝 flow
                     actions = [parser.OFPActionOutput(out_port)]
                     out = parser.OFPPacketOut(
                         datapath=datapath,
                         buffer_id=msg.buffer_id,
                         in_port=in_port,
                         actions=actions,
                         data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                     )
                     datapath.send_msg(out)
                     contiune
                     continue
                # 其他情形才自動下發 flow
                if out_port != ofproto.OFPP_FLOOD:
                     match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                     self.add_flow(datapath, 0, match, actions, msg.buffer_id)
                     continue
                else:
                     self.add_flow(datapath, 0, match, actions)

                # 發送封包
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(
                    datapath=datapath, 
                    buffer_id=msg.buffer_id,
                    in_port=in_port, 
                    actions=actions, 
                    data=data
                )

                datapath.send_msg(out)

            hub.sleep(0.05)
    def update_ip_connection_time(self, service_name, client_ip):
        """Update the timestamp for a client IP connection"""
        self.ip_connection_times.setdefault(service_name, {})
        self.ip_connection_times[service_name][client_ip] = datetime.now()

    def _container_monitor(self):
        """監控容器使用情況並管理生命週期"""
        while True:
            current_time = datetime.now()

            # 首先，清理過期的IP連接
            for service_name in list(self.ip_connection_times.keys()):
                active_ips = 0
                for ip in list(self.ip_connection_times[service_name].keys()):
                    if (current_time - self.ip_connection_times[service_name][ip]).total_seconds() <= self.IP_CONNECTION_TIMEOUT:
                        active_ips += 1
                    else:
                        # 清理過期的IP條目
                        if service_name in self.ip_container_map and ip in self.ip_container_map[service_name]:
                            del self.ip_container_map[service_name][ip]
                        del self.ip_connection_times[service_name][ip]

                # 更新活躍IP計數
                self.service_active_ip_count[service_name] = active_ips

            for service_name, containers in list(self.container_status.items()):
                # 跳過未正確初始化的服務
                if service_name not in self.ip_connection_times:
                    continue

                # 獲取服務配置以檢查多實例支持
                service_config = None
                for _, status in containers.items():
                    if "config" in status:
                        service_config = status["config"]
                        break

                if not service_config:
                    continue

                # 獲取容器配置
                max_containers = int(service_config.get('max_containers', 10))  # 最大容器數，默認10
                container_capacity = int(service_config.get('max', 1))  # 每個容器的最大IP數

                # 檢查是否支持多實例
                if service_config.get('multi', 'no') != 'yes':
                    continue

                # 檢查我們是否需要備用容器
                self._ensure_reserve_container(service_name)

                for container_name, status in list(containers.items()):
                    try:
                        container = self.docker_client.containers.get(container_name)

                        if container.status != "running":
                            # 如果是主容器，重啟它
                            if status.get("is_primary", False):
                                self.logger.info(f"重啟主容器 {container_name}")
                                container.restart()
                            else:
                                # 對於非主容器，只有在需要時才保留它們
                                # 檢查此容器是否有任何活躍的IP
                                container_ips = []
                                if service_name in self.ip_container_map:
                                    for ip, assigned_container in self.ip_container_map[service_name].items():
                                        if (assigned_container == container_name and 
                                            ip in self.ip_connection_times[service_name] and
                                            (current_time - self.ip_connection_times[service_name][ip]).total_seconds() <= self.IP_CONNECTION_TIMEOUT):
                                            container_ips.append(ip)

                                # 如果容器沒有活躍的IP，移除它
                                if not container_ips and (current_time - status["last_used"]).total_seconds() > self.CONTAINER_TIMEOUT:
                                    self.logger.info(f"移除不活躍的容器 {container_name}")
                                    stop_container(self, container_name, self.container_status)

                                    # 清理IP映射
                                    if service_name in self.ip_container_map:
                                        for ip, container in list(self.ip_container_map[service_name].items()):
                                            if container == container_name:
                                                del self.ip_container_map[service_name][ip]
                                # 否則重啟它
                                else:
                                    self.logger.info(f"重啟容器 {container_name}，有 {len(container_ips)} 個活躍IP")
                                    container.restart()

                    except docker.errors.NotFound:
                        # 如果容器不存在且是主容器，重新創建它
                        if status.get("is_primary", False):
                            self.logger.info(f"重新創建主容器 {container_name}")
                            if start_new_container(container_name, status["config"]):
                                status["last_used"] = datetime.now()
                        else:
                            # 移除不存在容器的記錄
                            if container_name in self.container_status[service_name]:
                                del self.container_status[service_name][container_name]

                            # 清理IP映射
                            if service_name in self.ip_container_map:
                                for ip, container in list(self.ip_container_map[service_name].items()):
                                    if container == container_name:
                                        del self.ip_container_map[service_name][ip]

                    except Exception as e:
                        self.logger.error(f"監控容器 {container_name} 時出錯: {e}")

            hub.sleep(10)

    def _ensure_reserve_container(self, service_name):
        """確保服務有可用的備用容器（如果需要）"""
        if service_name not in self.container_status:
            return

        # 獲取服務配置
        containers = list(self.container_status[service_name].items())
        if not containers:
            return

        # 獲取服務配置
        config = None
        for _, status in containers:
            if "config" in status:
                config = status["config"]
                break

        if not config:
            return

        # 檢查服務是否支持多實例
        if config.get('multi', 'no') != 'yes':
            return

        current_time = datetime.now()

        # 獲取容器配置
        max_containers = int(config.get('max_containers', 10))  # 最大容器數，默認10
        container_capacity = int(config.get('max', 1))  # 每個容器的最大IP數

        # 檢查所有容器的負載情況
        containers_with_space = 0
        total_non_primary = 0

        for container_name, status in self.container_status[service_name].items():
            if status.get("is_primary", False):
                continue

            total_non_primary += 1

            # 計算此容器的活躍IP數
            container_ips = 0
            for ip, assigned_container in self.ip_container_map.get(service_name, {}).items():
                if (assigned_container == container_name and 
                    ip in self.ip_connection_times.get(service_name, {}) and 
                    (current_time - self.ip_connection_times[service_name][ip]).total_seconds() <= self.IP_CONNECTION_TIMEOUT):
                    container_ips += 1

            # 如果容器有空間，計數加一
            if container_ips < container_capacity:
                containers_with_space += 1

        # 如果沒有空間的容器，且未達到最大容器數，創建一個新的
        if containers_with_space == 0 and total_non_primary < max_containers:
            container_index = len(self.container_status[service_name])
            new_container_name = f"{service_name}{container_index}"
            self.logger.info(f"為服務 {service_name} 創建新的備用容器 {new_container_name}。每容器最大IP數: {container_capacity}")

            if start_new_container(new_container_name, config):
                self.container_status[service_name][new_container_name] = {
                    "last_used": datetime.now(),
                    "ip": None,
                    "is_primary": False,
                    "config": config,
                    "active_connections": 0  # 為了向後兼容
                }
    def get_available_container(self, client_ip, port):
        """分配容器給指定的端口和客戶端IP"""
        if port not in self.docker_config or not self.docker_config[port]:
            self.logger.error(f"未知的服務端口 {port}")
            return None, None

        # 獲取服務配置
        service_config = self.docker_config[port][0]
        service_name = service_config.get('name', f'service_{port}')

        if service_name not in self.container_status:
            self.logger.error(f"服務 {service_name} 未初始化")
            return None, None

        current_time = datetime.now()

        # 初始化IP連接時間追踪
        self.ip_connection_times.setdefault(service_name, {})
        self.ip_container_map.setdefault(service_name, {})

        # 更新此IP的連接時間
        was_active_before = client_ip in self.ip_connection_times[service_name] and \
                        (current_time - self.ip_connection_times[service_name][client_ip]).total_seconds() <= self.IP_CONNECTION_TIMEOUT

        self.ip_connection_times[service_name][client_ip] = current_time

        # 如果此IP已經分配了容器
        if client_ip in self.ip_container_map[service_name]:
            container_name = self.ip_container_map[service_name][client_ip]
            if container_name in self.container_status[service_name]:
                # 更新容器的最後使用時間
                self.container_status[service_name][container_name]["last_used"] = current_time
                self.logger.info(f"使用現有容器 {container_name} 給客戶端 {client_ip}")
                return container_name, self.container_status[service_name][container_name]["config"]

        # 這是一個新IP或其先前的容器已消失
        # 如果這是一個新活躍的IP，則增加活躍IP計數
        if not was_active_before:
            self.service_active_ip_count.setdefault(service_name, 0)
            self.service_active_ip_count[service_name] += 1
            self.logger.info(f"服務 {service_name} 的新活躍IP {client_ip}。總活躍IP數: {self.service_active_ip_count[service_name]}")

        # 獲取容器容量和最大容器數
        max_containers = int(service_config.get('max_containers', 10))  # 最大容器數，默認10
        container_capacity = int(service_config.get('max', 1))  # 每個容器的最大IP數，從配置中讀取

        self.logger.info(f"服務 {service_name} 配置: 每容器最大IP數={container_capacity}, 最大容器數={max_containers}")

        # 檢查服務是否支持多實例
        multi_support = service_config.get('multi', 'no') == 'yes'

        # 找出所有運行中的容器以及每個容器當前服務的IP數量
        containers_with_ips = {}
        for container_name in self.container_status[service_name]:
            try:
                # 檢查容器是否運行中
                container = self.docker_client.containers.get(container_name)
                if container.status == "running":
                    # 計算分配給此容器的活躍IP
                    active_ips = []
                    for ip, assigned_container in self.ip_container_map[service_name].items():
                        if (assigned_container == container_name and 
                            ip in self.ip_connection_times[service_name] and 
                            (current_time - self.ip_connection_times[service_name][ip]).total_seconds() <= self.IP_CONNECTION_TIMEOUT):
                            active_ips.append(ip)

                    containers_with_ips[container_name] = {
                        "ips": active_ips,
                        "count": len(active_ips),
                        "is_primary": self.container_status[service_name][container_name].get("is_primary", False)
                    }
            except Exception as e:
                self.logger.error(f"檢查容器 {container_name} 狀態時出錯: {e}")

        # 首先，嘗試使用主容器（如果它有空間）
        primary_container = f"{service_name}0"
        if primary_container in containers_with_ips:
            if containers_with_ips[primary_container]["count"] < container_capacity:
                self.container_status[service_name][primary_container]["last_used"] = current_time
                self.ip_container_map[service_name][client_ip] = primary_container
                self.logger.info(f"將客戶端 {client_ip} 分配給主容器 {primary_container}，當前IP數: {containers_with_ips[primary_container]['count'] + 1}/{container_capacity}")
                return primary_container, self.container_status[service_name][primary_container]["config"]

        # 如果不支持多實例，則使用主容器
        if not multi_support:
            self.ip_container_map[service_name][client_ip] = primary_container
            self.logger.info(f"服務 {service_name} 不支持多實例，使用主容器給客戶端 {client_ip}")
            return primary_container, service_config

        # 找到負載最輕的容器，它還沒有達到容量
        available_containers = []
        for container_name, info in containers_with_ips.items():
            if info["count"] < container_capacity and not info["is_primary"]:
                available_containers.append((container_name, info["count"]))

        # 按IP數量排序（最少的優先）
        available_containers.sort(key=lambda x: x[1])

        # 如果有可用容器且未達到容量，使用它
        if available_containers:
            container_name = available_containers[0][0]
            self.container_status[service_name][container_name]["last_used"] = current_time
            self.ip_container_map[service_name][client_ip] = container_name
            new_count = containers_with_ips[container_name]["count"] + 1
            self.logger.info(f"將客戶端 {client_ip} 分配給現有容器 {container_name}，當前IP數: {new_count}/{container_capacity}")
            return container_name, self.container_status[service_name][container_name]["config"]

        # 計算當前非主容器的數量
        current_containers = len([c for c in containers_with_ips if not containers_with_ips[c]["is_primary"]])

        # 計算需要的容器數 (向上取整(活躍IP數 / 每容器容量))
        required_containers = math.ceil(self.service_active_ip_count.get(service_name, 0) / container_capacity)

        self.logger.info(f"服務 {service_name} 有 {self.service_active_ip_count.get(service_name, 0)} 個活躍IP，需要 {required_containers} 個容器，當前有 {current_containers} 個非主容器")

        # 檢查所有容器是否都已滿
        all_containers_full = True
        for container_name, info in containers_with_ips.items():
            if info["count"] < container_capacity:
                all_containers_full = False
                break

        # 只有當所有容器都已滿且未達到最大容器限制時才創建新容器
        if all_containers_full and current_containers < max_containers:
            container_index = len(self.container_status[service_name])
            new_container_name = f"{service_name}{container_index}"
            self.logger.info(f"為客戶端 {client_ip} 創建新容器 {new_container_name}。總活躍IP數: {self.service_active_ip_count.get(service_name, 0)}")

            if start_new_container(new_container_name, service_config):
                self.container_status[service_name][new_container_name] = {
                    "last_used": current_time,
                    "ip": None,  # 不再使用單一IP記錄
                    "is_primary": False,
                    "config": service_config,
                    "active_connections": 0  # 為了向後兼容
                }
                self.ip_container_map[service_name][client_ip] = new_container_name
                return new_container_name, service_config

        # 如果達到最大容器限制，則使用最不繁忙的容器
        least_busy_container = None
        min_ips = float('inf')

        for container_name, info in containers_with_ips.items():
            if not info["is_primary"] and info["count"] < min_ips:
                min_ips = info["count"]
                least_busy_container = container_name

        # 如果找到了最不繁忙的容器，使用它
        if least_busy_container:
            self.container_status[service_name][least_busy_container]["last_used"] = current_time
            self.ip_container_map[service_name][client_ip] = least_busy_container
            self.logger.info(f"將客戶端 {client_ip} 分配給最不繁忙的容器 {least_busy_container}，當前IP數: {min_ips + 1}/{container_capacity}")
            return least_busy_container, self.container_status[service_name][least_busy_container]["config"]

        # 如果沒有其他選擇，則使用主容器
        self.logger.info(f"無可用容器，將客戶端 {client_ip} 分配給主容器 {primary_container}")
        self.ip_container_map[service_name][client_ip] = primary_container
        return primary_container, service_config

    def update_container_status(self, service_name, container_name, client_ip):
        """更新容器的狀態信息"""
        if service_name in self.container_status and container_name in self.container_status[service_name]:
            container_status = self.container_status[service_name][container_name]
            container_status["last_used"] = datetime.now()

            if container_status["ip"] is None:
                container_status["ip"] = client_ip

            container_status["active_connections"] += 1

            self.ip_container_map.setdefault(service_name, {})
            self.ip_container_map[service_name][client_ip] = container_name

            self.logger.info(f"Updated container {container_name} for client {client_ip}, connections: {container_status['active_connections']}")

    def release_container(self, service_name, container_name, client_ip):
        """釋放容器連接"""
        if service_name in self.container_status and container_name in self.container_status[service_name]:
            container_status = self.container_status[service_name][container_name]

            if service_name in self.container_status and container_name in self.container_status[service_name]:
                self.container_status[service_name][container_name]["last_used"] = datetime.now()
                self.logger.info(f"Released container {container_name} for client {client_ip}")

            self.logger.info(f"Released container {container_name} for client {client_ip}, remaining connections: {container_status['active_connections']}")

    def hash_packet(self, pkt):
        """生成封包的哈希值"""
        hash_parts = []

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt:
            hash_parts.append(f"{eth_pkt.src}{eth_pkt.dst}{eth_pkt.ethertype}")

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            hash_parts.append(f"{ipv4_pkt.src}{ipv4_pkt.dst}{ipv4_pkt.proto}{ipv4_pkt.identification}")

        if not hash_parts:
            return None

        combined_key = "|".join(hash_parts)
        return hashlib.md5(combined_key.encode()).hexdigest()

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        """處理Snort警報事件"""
        msg = ev.msg
        pkt = packet.Packet(msg.pkt)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt or ipv4_pkt.dst != self.localIP:
            return

        pkt_hash = self.hash_packet(pkt)
        if pkt_hash is None:
            print("Invalid packet format.")
            return

        print(f"alert pkt:\n{pkt}\n{datetime.now()}\n")

        # 查找匹配的儲存封包
        for i, (stored_hash, stored_pkt, timestamp) in enumerate(self.packet_store):
            if stored_hash == pkt_hash:
                self.packet_store.pop(i)
                print(f"Matching packet found: {pkt_hash}\n")

                datapath = stored_pkt.datapath
                in_port = stored_pkt.match['in_port']
                pkt = packet.Packet(stored_pkt.data)

                # 處理TCP封包
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt and tcp_pkt.dst_port in self.docker_config:
                    self.handle_service_packet(pkt, datapath, in_port, stored_pkt, tcp_pkt.dst_port)
                    return

                # 儲存不符合條件的封包
                self.alert_packet(pkt)
                return

    def alert_packet(self, pkt):
        """將不安全封包保存到本地文件"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocol(ethernet.ethernet)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # 創建保存目錄
        output_dir = "./other"
        os.makedirs(output_dir, exist_ok=True)

        # 獲取other容器IP
        target_ip = getip.getcontainer_ip("other")
        if not target_ip:
            self.logger.error("Could not get IP for 'other' container")
            target_ip = "127.0.0.1"  # 使用默認值

        # 創建新的封包
        scapy_pkt = None

        if eth:
            scapy_pkt = Ether(src=eth.src, dst=eth.dst, type=eth.ethertype)

        if ipv4_pkt:
            ip_layer = IP(src=ipv4_pkt.src, dst=target_ip, proto=ipv4_pkt.proto)

            if scapy_pkt:
                scapy_pkt = scapy_pkt / ip_layer
            else:
                scapy_pkt = ip_layer

            self.logger.info(f"Alert packet: {ipv4_pkt.src} -> {target_ip}")

        # 添加適當的協議層
        if tcp_pkt:
            tcp_layer = TCP(sport=tcp_pkt.src_port, dport=tcp_pkt.dst_port)
            scapy_pkt = scapy_pkt / tcp_layer
        elif udp_pkt:
            udp_layer = UDP(sport=udp_pkt.src_port, dport=udp_pkt.dst_port)
            scapy_pkt = scapy_pkt / udp_layer
        elif icmp_pkt:
            icmp_layer = ICMP(type=icmp_pkt.type, code=icmp_pkt.code)
            scapy_pkt = scapy_pkt / icmp_layer

        if not scapy_pkt:
            self.logger.error("Could not create packet for saving")
            return

        # 生成文件名並保存
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = os.path.join(output_dir, f"alert_packet_{timestamp}.pcap")

        try:
            wrpcap(pcap_filename, scapy_pkt)
            self.logger.info(f"Packet saved to PCAP: {pcap_filename}")
        except Exception as e:
            self.logger.error(f"Error saving packet to PCAP: {e}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """處理交換機特性事件"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 安裝默認流表
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority,
            match=match, instructions=inst,
            idle_timeout=self.CONTAINER_TIMEOUT, hard_timeout=hard_timeout,
            buffer_id=buffer_id if buffer_id is not None else ofproto.OFP_NO_BUFFER
        )
        datapath.send_msg(mod)

    def handle_service_packet(self, pkt, datapath, in_port, msg, dst_port):
        """處理發送到服務的封包"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if not ipv4_pkt or not tcp_pkt:
            self.logger.error("Invalid packet format for service handling")
            return

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 獲取適合的容器
        container_name, service_config = self.get_available_container(ipv4_pkt.src, dst_port)

        if not container_name or not service_config:
            self.logger.error(f"No container available for port {dst_port}")
            self.alert_packet(pkt)  # 保存無法處理的封包
            return

        # 獲取容器IP
        target_ip = getip.getcontainer_ip(container_name)
        if not target_ip:
            self.logger.error(f"Could not get IP for container {container_name}")
            self.alert_packet(pkt)  # 保存無法處理的封包
            return

        # 設置目標端口
        target_port = service_config.get('target_port', dst_port)

        # 建立連接映射
        self.connection_map[(ipv4_pkt.src, tcp_pkt.src_port)] = (ipv4_pkt.dst, tcp_pkt.dst_port)

        self.logger.info(f"Traffic on port {dst_port}: {ipv4_pkt.src}:{tcp_pkt.src_port} -> " 
                      f"{target_ip}:{target_port} (Container: {container_name})")

        # 設置流表動作
        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(tcp_dst=target_port),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]

        # 發送封包
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id if hasattr(msg, 'buffer_id') else ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data if hasattr(msg, 'data') else None
        )

        datapath.send_msg(out)

    def return_packet(self, pkt, datapath, in_port, msg):
        """處理從容器返回的封包"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if not ipv4_pkt or not tcp_pkt:
            return

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 獲取原始連接信息
        original_src = self.connection_map.get((ipv4_pkt.dst, tcp_pkt.dst_port))

        self.logger.info(f"Incoming redirected traffic: {ipv4_pkt.src}:{tcp_pkt.src_port} -> {ipv4_pkt.dst}:{tcp_pkt.dst_port}")

        if original_src:
            original_src_ip, original_src_port = original_src

            self.logger.info(f"Spoofing back to: {original_src_ip}:{original_src_port}")

            # 設置流表動作
            actions = [
                parser.OFPActionSetField(ipv4_src=original_src_ip),
                parser.OFPActionSetField(tcp_src=original_src_port),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL)
            ]

            # 發送封包
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )

            datapath.send_msg(out)

            # 檢查是否是FIN或RST封包，釋放容器連接
            if tcp_pkt.bits & 0x01 or tcp_pkt.bits & 0x04:  # FIN or RST
                for service_name in self.container_status:
                    for container_name, status in self.container_status[service_name].items():
                        if status["ip"] == ipv4_pkt.dst:
                            self.release_container(service_name, container_name, ipv4_pkt.dst)
                            break
    def is_managed_traffic(self, msg):
        """檢查流量是否需要被OVS管理"""
        # 根據 in_port 判斷，通常 ens33 對應 port 1
        # ens34 如果沒有加入 OVS 就不會有 in_port
        try:
            in_port = msg.match['in_port']
            # 只處理來自 OVS 管理端口的流量
            return in_port is not None
        except:

            return False
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """處理封包輸入事件"""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if not self.is_managed_traffic(msg):
            return

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 獲取封包的IP和TCP層
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # 處理SSH流量和容器返回流量
        if tcp_pkt and ipv4_pkt:
            # 處理發送到本地SSH服務的流量
            if tcp_pkt.dst_port == 22 and ipv4_pkt.dst == self.localIP:
                self.handle_service_packet(pkt, datapath, in_port, msg, tcp_pkt.dst_port)
                return

            # 處理從容器返回的流量
            if tcp_pkt.src_port in [2222, 2223]:  # 容器SSH端口
                self.return_packet(pkt, datapath, in_port, msg)
                return

        # 處理與Snort相關的流量
        if ipv4_pkt and self.snort.getsnortip():
            if ipv4_pkt.dst == self.snort.getsnortip() or ipv4_pkt.src == self.snort.getsnortip():
                # 直接轉發Snort流量
                dst = eth.dst
                src = eth.src
                dpid = datapath.id

                self.mac_to_port.setdefault(dpid, {})
                self.mac_to_port[dpid][src] = in_port

                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD

                actions = [parser.OFPActionOutput(out_port)]

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=data
                )

                datapath.send_msg(out)
                return

        # 處理發送到本地IP的流量
        if ipv4_pkt and ipv4_pkt.dst == self.localIP:
            pkt_hash = self.hash_packet(pkt)
            current_time = datetime.now()

            if pkt_hash is None:
                return

            # 將封包儲存在等待檢查隊列中
            self.packet_store.append((pkt_hash, msg, current_time))
            return

        # 處理普通流量
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)
