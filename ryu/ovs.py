from __future__ import print_function
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import icmp
import snortlib
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, udp
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
import json
import controller_config

class SimpleSwitchSnort(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchSnort, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.snort_port = controller_config.snortport
        self.controller_port = controller_config.controller_port
        self.controller_ip = controller_config.controller_ip
        self.mac_to_port = {}
        self.connection_map = {}
        self.connection_ip = {}
        socket_config = {'unixsock': False,'port':self.snort_port}
        self.dockerid = {}
        self.docker_config,self.tcp_monitor_port,self.tcp_return_port,self.udp_monitor_port,self.udp_return_port = rc.config()
        self.packet_store = []
        self.monitor_thread = hub.spawn(self._monitor)
        self.localIP = self.get_ip_address('br0')
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        self.dockerstart = dockerstart.start()
        self.docker_client = docker.from_env()
        self.container_monitor = hub.spawn(self._container_monitor)
        self.allowed_snort_ip = None
        self.ip_connection_times = {}
        self.ip_container_map = {}
        self.IP_CONNECTION_TIMEOUT = controller_config.IP_CONNECTION_TIMEOUT
        self.service_active_ip_count = {}
        self.container_status = {}
        self.CONTAINER_TIMEOUT = controller_config.CONTAINER_TIMEOUT
        self.tmp_file = "connect_status.json.tmp"
        self.final_file = "connect_status.json"
        self.maxpercent = min(max(controller_config.maxpercent, 0.5), 1)
        self.initialize_services()


    def initialize_services(self):
        """初始化所有服務的容器管理"""
        container_check = []
        for port, configs in self.docker_config.items():
            if not configs:
                continue
            for config in configs:
                service_name = config.get('name', f'service_{port}')
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
                            "config": config,
                            "active_connections": 0
                        }
                        if container_name not in container_check:
                            self.logger.info(f"Found existing container: {container_name}")
                    else:
                        # 如果容器不存在，創建主容器
                        self.logger.info(f"Creating primary container for service: {service_name}")
                        if start_new_container(container_name, config):
                            self.container_status[service_name][container_name] = {
                                "last_used": datetime.now(),
                                "ip": None,
                                "is_primary": True,
                                "config": config,
                                "active_connections": 0
                            }

                    container_check.append(container_name)


                    # 對於支持多開的服務，預先創建一個備用容器
                    if config.get('multi', 'no') == 'yes':
                        reserve_container_name = f"{service_name}1"

                        try:
                            reserve_containers = self.docker_client.containers.list(filters={"name": reserve_container_name})

                            if not reserve_containers:
                                self.logger.info(f"Creating reserve container: {reserve_container_name}")
                                if start_new_container(reserve_container_name, config):
                                    self.container_status[service_name][reserve_container_name] = {
                                        "last_used": datetime.now(),
                                        "ip": None,
                                        "is_primary": False,
                                        "config": config,
                                        "active_connections": 0
                                    }
                            else:
                                self.container_status[service_name][reserve_container_name] = {
                                    "last_used": datetime.now(),
                                    "ip": None,
                                    "is_primary": False,
                                    "config": config,
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
            # 處理安全封包
            while self.packet_store and (datetime.now() - self.packet_store[0][2]).total_seconds() > 0.01:
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

    def cleanup_expired_connections(self, current_time, timeout=60):
        expired_keys = []

        for key, value in self.connection_map.items():
            last_time = value[1]
            if (current_time - last_time).total_seconds() > timeout:
                expired_keys.append(key)

        for key in expired_keys:
            del self.connection_map[key]
            #self.logger.info(f"Connection {key} expired and removed")

    def get_connections_by_src(self,src_ip,service_name):
        matches = []
        ports=[port
        for port, services in self.docker_config.items()
        if any(s["name"] == service_name for s in services)]
        for (ip, src_port, proto), (dst_info, ts) in self.connection_map.items():
            if ip == src_ip and dst_info[1] in ports:
                dst_ip, dst_port = dst_info
                matches.append({
                    "src_port": src_port,
                    "protocol": proto,
                    "dst_port": dst_port,
                })
        return matches
    def save_container_status_json(self):
        """將當前容器活躍 IP 資訊寫入 JSON"""
        status = {}
        current_time = datetime.now()

        for service_name, containers in self.container_status.items():
            status[service_name] = {}
            for container_name, container_info in containers.items():
                container_ips = []
                if service_name in self.ip_container_map:
                    for ip, assigned_container in self.ip_container_map[service_name].items():
                        if assigned_container == container_name:
                            last_time = self.ip_connection_times.get(service_name, {}).get(ip)
                            if last_time and (
                                    current_time - last_time).total_seconds() <= self.IP_CONNECTION_TIMEOUT:
                                container_ips.append(ip)

                status[service_name][container_name] = {
                    "active_ips": len(container_ips),
                    "ips":[{
                            "ip": ip,
                            "ports": self.get_connections_by_src(ip,service_name) # 每個 IP 都帶這些 port/proto
                        } for ip in container_ips],
                    "is_primary": container_info.get("is_primary", False),
                    "last_used": container_info.get("last_used", None).isoformat() if container_info.get(
                        "last_used") else None
                }
        with open(self.tmp_file, "w") as f:
            json.dump(status, f, indent=2)
        os.replace(self.tmp_file, self.final_file)

    def _container_monitor(self):
        """監控容器使用情況並管理生命週期"""
        while True:
            current_time = datetime.now()
            self.cleanup_expired_connections(current_time, timeout=self.IP_CONNECTION_TIMEOUT)

            # 首先，清理過期的IP連接
            for service_name in list(self.ip_connection_times.keys()):
                active_ips = 0
                for ip in list(self.ip_connection_times[service_name].keys()):
                    if (current_time - self.ip_connection_times[service_name][
                        ip]).total_seconds() <= self.IP_CONNECTION_TIMEOUT:
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

                # 檢查是否支持多實例
                if service_config.get('multi', 'no') != 'yes':
                    continue

                # 收集所有非主容器的活躍狀態
                inactive_containers = []
                active_containers = []

                for container_name, status in list(containers.items()):
                    try:
                        container = self.docker_client.containers.get(container_name)

                        # 如果是主容器，特殊處理
                        if status.get("is_primary", False):
                            if container.status != "running":
                                self.logger.info(f"Restarting primary container {container_name}")
                                container.restart()
                            continue

                        # 對於非主容器，檢查是否有活躍的IP
                        container_ips = []
                        if service_name in self.ip_container_map:
                            for ip, assigned_container in self.ip_container_map[service_name].items():
                                if (assigned_container == container_name and
                                        ip in self.ip_connection_times[service_name] and
                                        (current_time - self.ip_connection_times[service_name][
                                            ip]).total_seconds() <= self.IP_CONNECTION_TIMEOUT):
                                    container_ips.append(ip)

                        # 只處理運行中的容器
                        if container.status == "running":
                            if container_ips:
                                active_containers.append((container_name, container, status, container_ips))
                            else:
                                is_expired = (current_time - status[
                                    "last_used"]).total_seconds() > self.CONTAINER_TIMEOUT
                                inactive_containers.append((container_name, container, status, is_expired))
                        else:
                            # 容器已經停止，清理記錄
                            self.logger.debug(f"Container {container_name} is not running, removing from status")
                            if container_name in list(self.container_status[service_name].keys()):
                                del self.container_status[service_name][container_name]

                            # 清理IP映射
                            if service_name in self.ip_container_map:
                                for ip, container_item in list(self.ip_container_map[service_name].items()):
                                    if container_item == container_name:
                                        del self.ip_container_map[service_name][ip]

                    except docker.errors.NotFound:
                        # 容器不存在
                        if status.get("is_primary", False):
                            self.logger.info(f"Recreating primary container {container_name}")
                            if start_new_container(container_name, status["config"]):
                                status["last_used"] = datetime.now()
                        else:
                            # 移除不存在容器的記錄
                            self.logger.debug(f"Container {container_name} not found, removing from status")
                            if container_name in list(self.container_status[service_name].keys()):
                                del self.container_status[service_name][container_name]

                            # 清理IP映射
                            if service_name in self.ip_container_map:
                                for ip, container_item in list(self.ip_container_map[service_name].items()):
                                    if container_item == container_name:
                                        del self.ip_container_map[service_name][ip]

                    except Exception as e:
                        self.logger.error(f"Error monitoring container {container_name}: {e}")

                # 處理活躍容器
                for container_name, container, status, container_ips in active_containers:
                    if container.status != "running":
                        self.logger.info(
                            f"Restarting active container {container_name} with {len(container_ips)} active IPs")
                        container.restart()

                # 處理不活躍容器：保留一個作為備用，其他的停止
                if inactive_containers:
                    inactive_containers.sort()

                    # 保留第一個作為備用
                    reserve_container_name, reserve_container, reserve_status, _ = inactive_containers[0]

                    if reserve_container.status != "running":
                        self.logger.info(f"Starting reserve container {reserve_container_name}")
                        reserve_container.start()
                    else:
                        self.logger.debug(f"Reserve container {reserve_container_name} is ready")

                    # 停止其他超時的容器並立即清理記錄
                    for container_name, container, status, is_expired in inactive_containers[1:]:
                        if is_expired:
                            self.logger.info(f"Stopping inactive container: {container_name} (Timeout not used)")

                            # 停止容器
                            stop_container(self, container_name, self.container_status)

                            # 立即從狀態中刪除記錄
                            if container_name in list(self.container_status[service_name].keys()):
                                del self.container_status[service_name][container_name]
                                self.logger.debug(f"Removed {container_name} from container_status")

                            # 清理IP映射
                            if service_name in self.ip_container_map:
                                for ip, container_item in list(self.ip_container_map[service_name].items()):
                                    if container_item == container_name:
                                        del self.ip_container_map[service_name][ip]
                else:
                    # 沒有不活躍容器，確保有備用
                    self._ensure_reserve_container(service_name)
            self.save_container_status_json()
            hub.sleep(10)

    def get_next_available_container_name(self, service_name):
        """獲取下一個可用的容器名稱，重用已停止容器的編號"""
        # 獲取所有已存在的容器索引
        existing_indices = set()

        if service_name in self.container_status:
            for container_name in self.container_status[service_name].keys():
                # 從容器名中提取索引號
                if container_name.startswith(service_name):
                    index_str = container_name[len(service_name):]
                    if index_str.isdigit():
                        existing_indices.add(int(index_str))

        # 找到最小的未使用索引
        container_index = 0
        while container_index in existing_indices:
            container_index += 1

        return f"{service_name}{container_index}"
    def _ensure_reserve_container(self, service_name):
        """確保服務有可用的備用容器"""
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
        container_capacity = int(config.get('max', 10))  # 每個容器的最大IP數

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

        # 如果使用容器空間達到多少%，且未達到最大容器數，創建一個新的
        if (container_capacity - containers_with_space) / container_capacity > self.maxpercent and total_non_primary < max_containers:
            new_container_name = self.get_next_available_container_name(service_name)
            self.logger.info(
                f"Created new standby container {new_container_name} for service {service_name}. Max IPs per container: {container_capacity}"
            )

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
            self.logger.error(f"Unknown service port {port}")
            return None, None
        container_names = []
        service_configs = []
        for service_config in self.docker_config[port]:
            service_name = service_config.get('name', f'service_{port}')

            if service_name not in self.container_status:
                self.logger.error(f"Service {service_name} not initialized")
                container_names.append(None)
                service_configs.append(None)
                continue
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
                    #self.logger.info(f"Using existing container {container_name} for client {client_ip}")
                    container_names.append(container_name)
                    service_configs.append(self.container_status[service_name][container_name]["config"])
                    continue

            # 如果這是一個新活躍的IP，則增加活躍IP計數
            if not was_active_before:
                self.service_active_ip_count.setdefault(service_name, 0)
                self.service_active_ip_count[service_name] += 1
                self.logger.info(
                    f"New active IP {client_ip} for service {service_name}. Total active IPs: {self.service_active_ip_count[service_name]}"
                )

            # 獲取容器容量和最大容器數
            max_containers = int(service_config.get('max_containers', 10))  # 最大容器數，默認10
            container_capacity = int(service_config.get('max', 1))  # 每個容器的最大IP數，從配置中讀取

            self.logger.info(
                f"Service {service_name} configuration: max IPs per container={container_capacity}, max containers={max_containers}"
            )

            # 檢查服務是否支持多實例
            multi_support = service_config.get('multi', 'no') == 'yes'

            # 找出所有運行中的容器以及每個容器當前服務的IP數量
            containers_with_ips = {}
            for container_name in list(self.container_status[service_name].keys()):
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
                    self.logger.error(f"Error checking status of container {container_name}: {e}")

            # 首先，嘗試使用主容器（如果它有空間）
            primary_container = f"{service_name}0"
            if primary_container in containers_with_ips:
                if containers_with_ips[primary_container]["count"] < container_capacity:
                    self.container_status[service_name][primary_container]["last_used"] = current_time
                    self.ip_container_map[service_name][client_ip] = primary_container
                    self.logger.info(
                        f"Assigned client {client_ip} to primary container {primary_container}, current IP count: {containers_with_ips[primary_container]['count'] + 1}/{container_capacity}"
                    )
                    container_names.append(primary_container)
                    service_configs.append(self.container_status[service_name][primary_container]["config"])
                    continue
            # 如果不支持多實例，則使用主容器
            if not multi_support:
                self.ip_container_map[service_name][client_ip] = primary_container
                self.logger.info(
                    f"Service {service_name} does not support multiple instances, using primary container for client {client_ip}"
                )
                container_names.append(primary_container)
                service_configs.append(service_config)
                continue

            # 找到負載最輕的容器，它還沒有達到容量
            available_containers = []
            for container_name, info in containers_with_ips.items():
                if info["count"] < container_capacity and not info["is_primary"]:
                    available_containers.append((container_name, info["count"]))

            # 按IP數量排序（最少的優先）
            #available_containers.sort(key=lambda x: x[1])

            # 如果有可用容器且未達到容量，使用它
            if available_containers:
                container_name = available_containers[0][0]
                self.container_status[service_name][container_name]["last_used"] = current_time
                self.ip_container_map[service_name][client_ip] = container_name
                new_count = containers_with_ips[container_name]["count"] + 1
                self.logger.info(f"Client {client_ip} assigned to existing container {container_name}. Current usage: {new_count}/{container_capacity} IPs")
                container_names.append(container_name)
                service_configs.append(self.container_status[service_name][container_name]["config"])
                continue

            # 計算當前非主容器的數量
            current_containers = len([c for c in containers_with_ips if not containers_with_ips[c]["is_primary"]])

            # 計算需要的容器數 (向上取整(活躍IP數 / 每容器容量))
            required_containers = math.ceil(self.service_active_ip_count.get(service_name, 0) / container_capacity)

            self.logger.info(
                f"Service {service_name} has {self.service_active_ip_count.get(service_name, 0)} active IPs, "
                f"requires {required_containers} containers, currently {current_containers} non-primary containers running"
            )

            # 檢查所有容器是否都已滿
            all_containers_full = True
            for container_name, info in containers_with_ips.items():
                if info["count"] < container_capacity:
                    all_containers_full = False
                    break

            # 只有當所有容器都已滿且未達到最大容器限制時才創建新容器
            if all_containers_full and current_containers < max_containers:
                new_container_name = self.get_next_available_container_name(service_name)
                self.logger.info(
                    f"Created new container {new_container_name} for client {client_ip}. Total active IPs: {self.service_active_ip_count.get(service_name, 0)}"
                )

                if start_new_container(new_container_name, service_config):
                    self.container_status[service_name][new_container_name] = {
                        "last_used": current_time,
                        "ip": None,  # 不再使用單一IP記錄
                        "is_primary": False,
                        "config": service_config,
                        "active_connections": 0  # 為了向後兼容
                    }
                    self.ip_container_map[service_name][client_ip] = new_container_name
                    container_names.append(new_container_name)
                    service_configs.append(service_config)
                    continue

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
                self.logger.info(
                    f"Assigned client {client_ip} to the least busy container {least_busy_container}, current IP count: {min_ips + 1}/{container_capacity}"
                )
                container_names.append(least_busy_container)
                service_configs.append(self.container_status[service_name][least_busy_container]["config"])
                continue

            # 如果沒有其他選擇，則使用主容器
            self.logger.info(
                f"No available containers, assigning client {client_ip} to primary container {primary_container}"
            )
            self.ip_container_map[service_name][client_ip] = primary_container
            container_names.append(primary_container)
            service_configs.append(service_config)
            continue
        return container_names, service_configs

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
        """處理發送到服務的封包（支援 TCP 和 UDP）"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # 確認是 TCP 或 UDP 封包
        if not ipv4_pkt or (not tcp_pkt and not udp_pkt):
            self.logger.error("Invalid packet format for service handling")
            return

        # 判斷協議類型
        is_tcp = tcp_pkt is not None
        is_udp = udp_pkt is not None
        protocol_name = "TCP" if is_tcp else "UDP"

        # 獲取源端口
        src_port = tcp_pkt.src_port if is_tcp else udp_pkt.src_port

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 獲取適合的容器
        containers, services = self.get_available_container(ipv4_pkt.src, dst_port)

        for container_name, service_config in zip(containers, services):
            if not container_name or not service_config:
                self.logger.error(f"No container available for port {dst_port} ({protocol_name})")
                self.alert_packet(pkt)
                return

            # 獲取容器IP
            target_ip = getip.getcontainer_ip(container_name)
            if not target_ip:
                self.logger.error(f"Could not get IP for container {container_name}")
                self.alert_packet(pkt)
                return

            # 設置目標端口
            target_port = service_config.get('target_port', dst_port)
            current_time = datetime.now()
            # 建立連接映射（區分 TCP 和 UDP）
            connection_key = (ipv4_pkt.src, src_port, protocol_name)
            entry = self.connection_map.get(connection_key)

            if entry and entry[0] == (ipv4_pkt.dst, dst_port):
                entry[1] = current_time
            else:
                self.connection_map[connection_key] = [(ipv4_pkt.dst, dst_port), current_time]

            # 設置流表動作（根據協議類型）
            actions = [parser.OFPActionSetField(ipv4_dst=target_ip)]

            if is_tcp:
                actions.append(parser.OFPActionSetField(tcp_dst=target_port))
            elif is_udp:
                actions.append(parser.OFPActionSetField(udp_dst=target_port))

            actions.append(parser.OFPActionOutput(ofproto.OFPP_NORMAL))

            # 發送封包
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id if hasattr(msg, 'buffer_id') else ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data if hasattr(msg, 'data') else None
            )
            datapath.send_msg(out)

            #self.logger.info(f"{protocol_name} Traffic on port {dst_port}: {ipv4_pkt.src}:{src_port} -> "
                             #f"{target_ip}:{target_port} (Container: {container_name})")

    def return_packet(self, pkt, datapath, in_port, msg):
        """處理從容器返回的封包（支援 TCP 和 UDP）"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # 確認是 TCP 或 UDP 封包
        if not ipv4_pkt or (not tcp_pkt and not udp_pkt):
            return

        # 判斷協議類型
        is_tcp = tcp_pkt is not None
        is_udp = udp_pkt is not None
        protocol_name = "TCP" if is_tcp else "UDP"

        # 獲取目標端口（用於查找原始連接）
        dst_port = tcp_pkt.dst_port if is_tcp else udp_pkt.dst_port

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 獲取原始連接信息（使用包含協議的 key）
        connection_key = (ipv4_pkt.dst, dst_port, protocol_name)
        original_src = self.connection_map.get(connection_key)

        if original_src:
            original_src_ip, original_src_port = original_src[0]

            # 設置流表動作（根據協議類型）
            actions = [parser.OFPActionSetField(ipv4_src=original_src_ip)]

            if is_tcp:
                actions.append(parser.OFPActionSetField(tcp_src=original_src_port))
            elif is_udp:
                actions.append(parser.OFPActionSetField(udp_src=original_src_port))

            actions.append(parser.OFPActionOutput(ofproto.OFPP_NORMAL))

            # 發送封包
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)

            # 處理連接釋放
            if is_tcp:
                if tcp_pkt.bits & 0x01 or tcp_pkt.bits & 0x04:  # FIN or RST
                    for service_name in self.container_status:
                        for container_name, status in self.container_status[service_name].items():
                            if status["ip"] == ipv4_pkt.dst:
                                self.release_container(service_name, container_name, ipv4_pkt.dst)
                                break

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """處理封包輸入事件"""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # 1. 檢查 in_port
        try:
            in_port = msg.match['in_port']
        except KeyError:
            self.logger.warning("No in_port in match, dropped.")
            return

        # 2. 檢查 msg.data 是否存在
        if msg.data is None:
            self.logger.warning("msg.data is None, dropped.")
            return

        # 3. 檢查數據長度（OpenFlow header 至少需要 8 bytes）
        if len(msg.data) < 8:
            self.logger.warning(f"Received too short data (len={len(msg.data)}), dropped.")
            return

        # 4. 檢查是否是有效的以太網幀（至少 14 bytes）
        if len(msg.data) < 14:
            self.logger.warning(f"Data too short for Ethernet frame (len={len(msg.data)}), dropped.")
            return

        # 5. 安全地解析封包
        try:
            pkt = packet.Packet(msg.data)
        except Exception as e:
            self.logger.error(f"Failed to parse packet: {e}")
            return

        # 6. 檢查是否包含以太網頭部
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt:
            self.logger.warning("No Ethernet header found, dropped.")
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 獲取封包的IP和TCP層
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt and ipv4_pkt:
            # 處理發送到honeypot服務的流量
            if udp_pkt.dst_port in self.udp_monitor_port and ipv4_pkt.dst == self.localIP:
                self.handle_service_packet(pkt, datapath, in_port, msg, udp_pkt.dst_port)
                return

            # 處理從容器返回的流量
            if udp_pkt.src_port in self.udp_return_port:
                self.return_packet(pkt, datapath, in_port, msg)
                return

        # 處理SSH流量和容器返回流量
        if tcp_pkt and ipv4_pkt:
            if ipv4_pkt and self.snort.getsnortip() and self.allowed_snort_ip is None:
                self.allowed_snort_ip = self.snort.getsnortip()
            # 處理發送到honeypot服務的流量
            if tcp_pkt.dst_port in self.tcp_monitor_port and ipv4_pkt.dst == self.localIP:
                self.handle_service_packet(pkt, datapath, in_port, msg, tcp_pkt.dst_port)
                return

            # 處理從容器返回的流量
            if tcp_pkt.src_port in self.tcp_return_port:
                self.return_packet(pkt, datapath, in_port, msg)
                return

            if tcp_pkt.dst_port == self.snort_port  and (self.allowed_snort_ip != ipv4_pkt.src or self.allowed_snort_ip != ipv4_pkt.dst):
                self.logger.warning(f"reject from {ipv4_pkt.src} snort or packets received from port {tcp_pkt.dst_port}")
                self.alert_packet(pkt)
                return

            if tcp_pkt.dst_port == self.controller_port and (self.controller_ip != ipv4_pkt.src or self.controller_ip != ipv4_pkt.dst):
                self.logger.warning(f"reject from {ipv4_pkt.src} controller or packets received from port {tcp_pkt.dst_port}")
                self.alert_packet(pkt)
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
