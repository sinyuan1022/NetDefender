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
from newcontainer import * 
from stopcontainer import * 
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
        self.container_status = {}  # {service_name: {container_name: {"last_used": timestamp, "ip": client_ip, "connections": count}}}
        self.ip_container_map = {}  # {service_name: {client_ip: container_name}}
        self.CONTAINER_TIMEOUT = 300  # 5分鐘
        self.initialize_services()
        self.logger = self.get_logger()

    def get_logger(self):
        """Get a logger instance"""
        import logging
        logger = logging.getLogger('SimpleSwitchSnort')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger
        
    def initialize_services(self):
        """初始化所有服務的容器管理"""
        for port, configs in self.docker_config.items():
            service_name = configs[0].get('name', f'service_{port}')
            self.container_status[service_name] = {}
            self.ip_container_map[service_name] = {}
            
            # 檢查主要容器是否存在
            container_name = f"{service_name}0"
            existing_containers = self.docker_client.containers.list(filters={"name": container_name}, all=True)
            
            # 如果主容器不存在或不在運行狀態，創建它
            if not existing_containers or existing_containers[0].status != "running":
                self.logger.info(f"Starting primary container {container_name}")
                start_new_container(container_name, configs[0])
            
            # 更新狀態
            self.container_status[service_name][container_name] = {
                "last_used": datetime.now(),
                "ip": None,
                "is_primary": True,
                "config": configs[0],
                "connections": 0
            }
            
            # 如果設置允許多開且需要預留容器，創建一個預留容器
            if configs[0].get('multi', 'no').lower() == 'yes':
                spare_container = f"{service_name}1"
                existing_spare = self.docker_client.containers.list(filters={"name": spare_container}, all=True)
                
                if not existing_spare or existing_spare[0].status != "running":
                    self.logger.info(f"Starting spare container {spare_container}")
                    start_new_container(spare_container, configs[0])
                
                self.container_status[service_name][spare_container] = {
                    "last_used": datetime.now(),
                    "ip": None,
                    "is_primary": False,
                    "is_spare": True,
                    "config": configs[0],
                    "connections": 0
                }

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
        while True:
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
                
                self.mac_to_port.setdefault(dpid, {})
                self.mac_to_port[dpid][src] = in_port
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
                
                actions = [parser.OFPActionOutput(out_port)]
                '''
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        continue
                    else:
                        self.add_flow(datapath, 1, match, actions)
                '''
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
                # 檢查是否需要建立備用容器
                has_spare = False
                primary_container = None
                service_config = None
                
                for container_name, status in containers.items():
                    if status.get("is_primary", False):
                        primary_container = container_name
                        service_config = status["config"]
                    if status.get("is_spare", False) and status["connections"] == 0:
                        has_spare = True
                
                # 如果支持多開且沒有備用容器，創建一個
                if service_config and service_config.get('multi', 'no').lower() == 'yes' and not has_spare:
                    spare_idx = 1
                    while f"{service_name}{spare_idx}" in containers:
                        spare_idx += 1
                    
                    spare_container = f"{service_name}{spare_idx}"
                    self.logger.info(f"Creating spare container {spare_container}")
                    start_new_container(spare_container, service_config)
                    
                    self.container_status[service_name][spare_container] = {
                        "last_used": datetime.now(),
                        "ip": None,
                        "is_primary": False,
                        "is_spare": True,
                        "config": service_config,
                        "connections": 0
                    }
                
                # 檢查每個容器的狀態
                for container_name, status in list(containers.items()):
                    try:
                        container = self.docker_client.containers.get(container_name)
                        
                        # 處理主容器
                        if status.get("is_primary", False):
                            if container.status != "running":
                                self.logger.info(f"Restarting primary container {container_name}")
                                container.restart()
                        # 處理非主容器
                        else:
                            # 如果是備用容器，跳過超時檢查
                            if status.get("is_spare", False):
                                continue
                                
                            # 如果非備用容器且無連接且超時，移除它
                            if status["connections"] == 0 and \
                               (current_time - status["last_used"]).total_seconds() > self.CONTAINER_TIMEOUT:
                                self.logger.info(f"Removing inactive container {container_name}")
                                container.remove(force=True)
                                del self.container_status[service_name][container_name]
                                
                                if status["ip"] and status["ip"] in self.ip_container_map.get(service_name, {}):
                                    del self.ip_container_map[service_name][status["ip"]]
                    
                    except docker.errors.NotFound:
                        # 如果容器不存在且是主要容器，重新創建
                        if status.get("is_primary", False):
                            self.logger.info(f"Recreating primary container {container_name}")
                            start_new_container(container_name, status["config"])
                        else:
                            # 如果不是主容器且找不到，從狀態中移除
                            if container_name in self.container_status[service_name]:
                                del self.container_status[service_name][container_name]
            
            hub.sleep(10)

    def get_available_container(self, client_ip, port):
        """為指定服務和客戶端 IP 分配容器"""
        # 找到對應服務名稱
        for service_config in self.docker_config.get(port, []):
            service_name = service_config.get('name', f'service_{port}')
            
            # 如果服務未初始化，則初始化
            if service_name not in self.container_status:
                self.container_status[service_name] = {}
                self.ip_container_map[service_name] = {}
                
                # 創建主容器
                container_name = f"{service_name}0"
                start_new_container(container_name, service_config)
                self.container_status[service_name][container_name] = {
                    "last_used": datetime.now(),
                    "ip": None,
                    "is_primary": True,
                    "config": service_config,
                    "connections": 0
                }
                
                # 如果允許多開，創建備用容器
                if service_config.get('multi', 'no').lower() == 'yes':
                    spare_container = f"{service_name}1"
                    start_new_container(spare_container, service_config)
                    self.container_status[service_name][spare_container] = {
                        "last_used": datetime.now(),
                        "ip": None,
                        "is_primary": False,
                        "is_spare": True,
                        "config": service_config,
                        "connections": 0
                    }
            
            # 如果該 IP 已有指定的容器
            if client_ip in self.ip_container_map.get(service_name, {}):
                container_name = self.ip_container_map[service_name][client_ip]
                if container_name in self.container_status[service_name]:
                    self.update_container_usage(service_name, container_name)
                    return container_name, self.container_status[service_name][container_name]["config"]
            
            # 尋找可用容器 - 首先檢查有無連接數小於最大值的容器
            max_connections = service_config.get('max', 1)
            for container_name, status in self.container_status[service_name].items():
                # 跳過備用容器
                if status.get("is_spare", False):
                    continue
                    
                # 如果連接數小於最大值，使用這個容器
                if status["connections"] < max_connections:
                    if status["ip"] is None:
                        status["ip"] = client_ip
                    self.ip_container_map.setdefault(service_name, {})[client_ip] = container_name
                    self.update_container_usage(service_name, container_name)
                    return container_name, status["config"]
            
            # 如果所有容器都達到最大連接數且允許多開，使用備用容器
            if service_config.get('multi', 'no').lower() == 'yes':
                # 尋找備用容器
                spare_container = None
                for container_name, status in self.container_status[service_name].items():
                    if status.get("is_spare", False) and status["connections"] == 0:
                        spare_container = container_name
                        break
                
                if spare_container:
                    # 將備用容器標記為非備用
                    self.container_status[service_name][spare_container]["is_spare"] = False
                    self.container_status[service_name][spare_container]["ip"] = client_ip
                    self.ip_container_map.setdefault(service_name, {})[client_ip] = spare_container
                    self.update_container_usage(service_name, spare_container)
                    
                    # 創建新的備用容器
                    next_id = int(spare_container.replace(service_name, "")) + 1
                    new_spare = f"{service_name}{next_id}"
                    start_new_container(new_spare, service_config)
                    self.container_status[service_name][new_spare] = {
                        "last_used": datetime.now(),
                        "ip": None,
                        "is_primary": False,
                        "is_spare": True,
                        "config": service_config,
                        "connections": 0
                    }
                    
                    return spare_container, service_config
                    
            # 如果沒有可用容器，返回 None
            return None, service_config
        
        # 如果沒有找到對應的服務配置，返回 None
        return None, None

    def update_container_usage(self, service_name, container_name):
        """更新容器的使用狀態"""
        if service_name in self.container_status and container_name in self.container_status[service_name]:
            self.container_status[service_name][container_name]["last_used"] = datetime.now()
            self.container_status[service_name][container_name]["connections"] += 1
            self.logger.info(f"Updated usage for container {container_name}, connections: {self.container_status[service_name][container_name]['connections']}")

    def release_container_connection(self, service_name, container_name):
        """釋放容器連接"""
        if service_name in self.container_status and container_name in self.container_status[service_name]:
            if self.container_status[service_name][container_name]["connections"] > 0:
                self.container_status[service_name][container_name]["connections"] -= 1
                self.logger.info(f"Released connection for container {container_name}, connections: {self.container_status[service_name][container_name]['connections']}")

    def hash_packet(self, pkt):
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
        msg = ev.msg
        pkt = packet.Packet(msg.pkt)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if ipv4_pkt and ipv4_pkt.dst == self.localIP:
            pkt_hash = self.hash_packet(pkt)
            if pkt_hash is None:
                print("Invalid packet format.")
                return
                
            print(f"alert pkt:\n{pkt}\n{datetime.now()}\n")
            
            for i, (stored_hash, stored_pkt, timestamp) in enumerate(self.packet_store):
                if stored_hash == pkt_hash:
                    self.packet_store.pop(i)
                    print(f"Matching packet found: {pkt_hash}\n")
                    
                    datapath = stored_pkt.datapath
                    in_port = stored_pkt.match['in_port']
                    pkt = packet.Packet(stored_pkt.data)
                    
                    # 檢查是否有TCP封包
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    if tcp_pkt:
                        dst_port = tcp_pkt.dst_port
                        if dst_port in self.docker_config:
                            self.handle_alert_packet(pkt, datapath, in_port, stored_pkt, dst_port)
                            return
                    
                    # 如果不是TCP封包或沒有對應的服務
                    self.save_to_other(pkt)
                    return

    def handle_alert_packet(self, pkt, datapath, in_port, msg, dst_port):
        """處理警報封包並轉發到適當的容器"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        client_ip = ipv4_pkt.src
        
        # 尋找對應服務的配置
        service_config = self.docker_config.get(dst_port, [{}])[0]
        service_name = service_config.get('name', f'service_{dst_port}')
        
        # 取得可用容器
        container_name, config = self.get_available_container(client_ip, dst_port)
        
        if container_name:
            # 獲取容器 IP
            target_ip = getip.getcontainer_ip(container_name)
            if not target_ip:
                self.logger.error(f"Could not get IP for container {container_name}")
                self.save_to_other(pkt)
                return
                
            target_port = config.get('target_port', dst_port)
            
            # 設置連接映射
            self.connection_map[(ipv4_pkt.src, tcp_pkt.src_port)] = (ipv4_pkt.dst, tcp_pkt.dst_port)
            
            self.logger.info(f"Redirecting alert traffic on port {dst_port}: {ipv4_pkt.src}:{tcp_pkt.src_port} -> " 
                            f"{target_ip}:{target_port} (Container: {container_name})")
            
            # 轉發封包到容器
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            
            actions = [
                parser.OFPActionSetField(ipv4_dst=target_ip),
                parser.OFPActionSetField(tcp_dst=target_port),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL)
            ]
            
            out = parser.OFPPacketOut(
                datapath=datapath, 
                buffer_id=msg.buffer_id,
                in_port=in_port, 
                actions=actions, 
                data=msg.data
            )
            datapath.send_msg(out)
        else:
            # 如果沒有可用容器，將封包儲存到其他資料夾
            self.logger.info(f"No available container for port {dst_port}, saving packet to ./other")
            self.save_to_other(pkt)

    def save_to_other(self, pkt):
        """將封包儲存到 ./other 資料夾"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocol(ethernet.ethernet)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        # 確保資料夾存在
        output_dir = "./other"
        os.makedirs(output_dir, exist_ok=True)
        
        # 建立 Scapy 封包
        scapy_pkt = Ether(src=eth.src, dst=eth.dst, type=eth.ethertype)
        
        if ipv4_pkt:
            ip_layer = IP(src=ipv4_pkt.src, dst=ipv4_pkt.dst, proto=ipv4_pkt.proto)
            scapy_pkt = scapy_pkt / ip_layer
            
            if tcp_pkt:
                tcp_layer = TCP(sport=tcp_pkt.src_port, dport=tcp_pkt.dst_port)
                scapy_pkt = scapy_pkt / tcp_layer
            elif udp_pkt:
                udp_layer = UDP(sport=udp_pkt.src_port, dport=udp_pkt.dst_port)
                scapy_pkt = scapy_pkt / udp_layer
            elif icmp_pkt:
                icmp_layer = ICMP(type=icmp_pkt.type, code=icmp_pkt.code)
                scapy_pkt = scapy_pkt / icmp_layer
        
        # 儲存為 PCAP
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = os.path.join(output_dir, f"alert_packet_{timestamp}.pcap")
        wrpcap(pcap_filename, scapy_pkt)
        self.logger.info(f"Packet saved to PCAP: {pcap_filename}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, 
                buffer_id=buffer_id,
                priority=priority, 
                match=match,
                instructions=inst
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, 
                priority=priority,
                match=match, 
                instructions=inst
            )
        datapath.send_msg(mod)

    def handle_service_packet(self, pkt, datapath, in_port, msg, dst_port):
        """處理服務封包"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        client_ip = ipv4_pkt.src
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # 獲取容器
        container_name, config = self.get_available_container(client_ip, dst_port)
        
        if not container_name:
            # 如果沒有可用容器，將封包存到其他資料夾
            self.save_to_other(pkt)
            return
        
        # 獲取容器 IP
        target_ip = getip.getcontainer_ip(container_name)
        if not target_ip:
            self.logger.error(f"Could not get IP for container {container_name}")
            self.save_to_other(pkt)
            return
            
        # 獲取目標端口
        target_port = config.get('target_port', dst_port)
        
        # 建立連接映射
        self.connection_map[(ipv4_pkt.src, tcp_pkt.src_port)] = (ipv4_pkt.dst, tcp_pkt.dst_port)
        
        self.logger.info(f"Traffic on port {dst_port}: {ipv4_pkt.src}:{tcp_pkt.src_port} -> " 
                        f"{target_ip}:{target_port} (Container: {container_name})")
        
        # 轉發封包到容器
        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(tcp_dst=target_port),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        
        out = parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=msg.buffer_id,
            in_port=in_port, 
            actions=actions, 
            data=msg.data
        )
        datapath.send_msg(out)

    def return_packet(self, pkt, datapath, in_port, msg):
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # 查找原始連接
        original_src = self.connection_map.get((ipv4_pkt.dst, tcp_pkt.dst_port))
        self.logger.info("Incoming redirected traffic: %s:%s -> %s:%s", 
                        ipv4_pkt.src, tcp_pkt.src_port, 
                        ipv4_pkt.dst, tcp_pkt.dst_port)
        
        if original_src:
            original_src_ip, original_src_port = original_src
            self.logger.info("Spoofing back to: %s:%s", original_src_ip, original_src_port)
            
            actions = [
                parser.OFPActionSetField(ipv4_src=original_src_ip),
                parser.OFPActionSetField(tcp_src=original_src_port),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL)
            ]
            
            out = parser.OFPPacketOut(
                datapath=datapath, 
                buffer_id=msg.buffer_id,
                in_port=in_port, 
                actions=actions, 
                data=msg.data
            )
            datapath.send_msg(out)
            
            # 當連接結束時，釋放容器連接計數
            for service_name, ip_map in self.ip_container_map.items():
                if ipv4_pkt.dst in ip_map:
                    container_name = ip_map[ipv4_pkt.dst]
                    self.release_container_connection(service_name, container_name)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        
        # 提取封包信息
        eth = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        # 處理特定服務的封包
        if tcp_pkt and ipv4_pkt:
            # 處理SSH和其他配置的服務
            if tcp_pkt.dst_port in self.docker_config and ipv4_pkt.dst == self.localIP:
                self.handle_service_packet(pkt, datapath, in_port, msg, tcp_pkt.dst_port)
                return
                
            # 處理從容器返回的封包
            if any(port in [container_config.get('target_port', 22) 
                            for service_configs in self.docker_config.values() 
                            for container_config in service_configs]
                  for port in [tcp_pkt.src_port]):
                self.return_packet(pkt, datapath, in_port, msg)
                return
        
        # 處理與Snort相關的封包
        if ipv4_pkt and self.snort.getsnortip():
            if ipv4_pkt.dst == self.snort.getsnortip() or ipv4_pkt.src == self.snort.getsnortip():
                # 允許Snort封包通過
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
        
        # 將目標為本地的封包加入監控列表
        if ipv4_pkt and ipv4_pkt.dst == self.localIP:
            pkt_hash = self.hash_packet(pkt)
            current_time = datetime.now()
            
            if pkt_hash is None:
                return
                
            self.packet_store.append((pkt_hash, msg, current_time))
            return
        
        # 處理普通封包
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
        
        # 添加流表項
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        
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
