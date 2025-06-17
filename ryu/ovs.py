from __future__ import print_function
import array
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
import snortlib
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from ryu.ofproto import ether, inet
from ryu.lib import hub
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

class SimpleSwitchSnort(app_manager.RyuApp):
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
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        continue
                    else:
                        self.add_flow(datapath, 1, match, actions)
                
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

    def _container_monitor(self):
        """監控容器使用狀況"""
        while True:
            current_time = datetime.now()
            
            for service_name, containers in list(self.container_status.items()):
                # 檢查是否需要為該服務建立備用容器
                self._ensure_reserve_container(service_name)
                
                for container_name, status in list(containers.items()):
                    # 更新容器狀態
                    try:
                        container = self.docker_client.containers.get(container_name)
                        
                        if container.status != "running":
                            # 如果是主要容器且沒在運行，重啟它
                            if status.get("is_primary", False):
                                self.logger.info(f"Restarting primary container {container_name}")
                                container.restart()
                            else:
                                # 如果是非主要容器且超時，移除它
                                if (current_time - status["last_used"]).total_seconds() > self.CONTAINER_TIMEOUT and status["active_connections"] == 0:
                                    self.logger.info(f"Removing inactive container {container_name}")
                                    stop_container(self, container_name, self.container_status)
                                    
                                    if status["ip"] and service_name in self.ip_container_map and status["ip"] in self.ip_container_map[service_name]:
                                        del self.ip_container_map[service_name][status["ip"]]
                    except docker.errors.NotFound:
                        # 如果容器不存在且是主要容器，重新創建
                        if status.get("is_primary", False):
                            self.logger.info(f"Recreating primary container {container_name}")
                            if start_new_container(container_name, status["config"]):
                                status["last_used"] = datetime.now()
                                status["active_connections"] = 0
                        else:
                            # 移除不存在的容器記錄
                            if container_name in self.container_status[service_name]:
                                del self.container_status[service_name][container_name]
                                
                            if status["ip"] and service_name in self.ip_container_map and status["ip"] in self.ip_container_map[service_name]:
                                del self.ip_container_map[service_name][status["ip"]]
                    except Exception as e:
                        self.logger.error(f"Error monitoring container {container_name}: {e}")
            
            hub.sleep(10)

    def _ensure_reserve_container(self, service_name):
        """確保服務有一個備用容器"""
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
            
        # 檢查是否支持多開
        if config.get('multi', 'no') != 'yes':
            return
            
        # 計算主要和備用容器數量
        primary_count = 0
        reserve_count = 0
        active_count = 0
        
        for container_name, status in containers:
            if status.get("is_primary", False):
                primary_count += 1
            elif status["active_connections"] == 0:
                reserve_count += 1
            
            if status["active_connections"] > 0:
                active_count += 1
        
        # 如果沒有備用容器，創建一個
        if reserve_count == 0:
            container_index = len(containers)
            new_container_name = f"{service_name}{container_index}"
            
            self.logger.info(f"Creating new reserve container {new_container_name} for service {service_name}")
            
            if start_new_container(new_container_name, config):
                self.container_status[service_name][new_container_name] = {
                    "last_used": datetime.now(),
                    "ip": None,
                    "is_primary": False,
                    "config": config,
                    "active_connections": 0
                }

    def get_available_container(self, client_ip, port):
        """為指定端口和客戶端 IP 分配容器"""
        if port not in self.docker_config or not self.docker_config[port]:
            self.logger.error(f"Unknown service for port {port}")
            return None, None
            
        # 獲取服務配置
        service_config = self.docker_config[port][0]
        service_name = service_config.get('name', f'service_{port}')
        
        if service_name not in self.container_status:
            self.logger.error(f"Service {service_name} not initialized")
            return None, None
        
        # 如果該 IP 已有指定的容器
        if service_name in self.ip_container_map and client_ip in self.ip_container_map[service_name]:
            container_name = self.ip_container_map[service_name][client_ip]
            
            if container_name in self.container_status[service_name]:
                self.update_container_status(service_name, container_name, client_ip)
                return container_name, self.container_status[service_name][container_name]["config"]
        
        # 檢查是否可以使用主要容器
        primary_container = f"{service_name}0"
        
        if primary_container in self.container_status[service_name]:
            primary_status = self.container_status[service_name][primary_container]
            
            # 如果主容器未被分配或連接數低於最大值
            if primary_status["ip"] is None:
                primary_status["ip"] = client_ip
                primary_status["active_connections"] = 1
                primary_status["last_used"] = datetime.now()
                
                self.ip_container_map.setdefault(service_name, {})
                self.ip_container_map[service_name][client_ip] = primary_container
                
                return primary_container, primary_status["config"]
            
            # 如果是同一個IP繼續使用主容器
            if primary_status["ip"] == client_ip:
                primary_status["active_connections"] += 1
                primary_status["last_used"] = datetime.now()
                return primary_container, primary_status["config"]
        
        # 檢查服務是否支持多開
        if service_config.get('multi', 'no') != 'yes':
            return primary_container, service_config
        
        # 檢查是否達到最大容器限制
        max_containers = int(service_config.get('max', 1))
        current_active = sum(1 for status in self.container_status[service_name].values() 
                           if status["active_connections"] > 0)
        
        if current_active >= max_containers:
            self.logger.warning(f"Reached maximum container limit for service {service_name}")
            return primary_container, service_config
        
        # 尋找可用的備用容器
        for container_name, status in self.container_status[service_name].items():
            if not status.get("is_primary", False) and status["active_connections"] == 0:
                status["ip"] = client_ip
                status["active_connections"] = 1
                status["last_used"] = datetime.now()
                
                self.ip_container_map.setdefault(service_name, {})
                self.ip_container_map[service_name][client_ip] = container_name
                
                return container_name, status["config"]
        
        # 如果沒有可用的備用容器，創建新容器
        container_index = len(self.container_status[service_name])
        new_container_name = f"{service_name}{container_index}"
        
        self.logger.info(f"Creating new container {new_container_name} for client {client_ip}")
        
        if start_new_container(new_container_name, service_config):
            self.container_status[service_name][new_container_name] = {
                "last_used": datetime.now(),
                "ip": client_ip,
                "is_primary": False,
                "config": service_config,
                "active_connections": 1
            }
            
            self.ip_container_map.setdefault(service_name, {})
            self.ip_container_map[service_name][client_ip] = new_container_name
            
            # 確保始終有一個備用容器
            self._ensure_reserve_container(service_name)
            
            return new_container_name, service_config
        
        # 如果無法創建新容器，使用主容器
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
            
            if container_status["active_connections"] > 0:
                container_status["active_connections"] -= 1
                
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
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """添加流表項目"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """處理封包輸入事件"""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
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
