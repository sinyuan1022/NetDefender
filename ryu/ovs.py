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
from scapy.layers.inet import IP, ICMP
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
        self.connection_map = {}  # {(src_ip, src_port): (dst_ip, dst_port)}
        self.connection_ip = {}   # {ip: mapped_ip}
        self.service_connections = {}  # {(src_ip, src_port): "service_name"}
        socket_config = {'unixsock': False}
        self.dockerid = {}
        self.docker_config = rc.config()
        self.packet_store = []  # [(pkt_hash, msg, timestamp)]
        self.monitor_thread = hub.spawn(self._monitor)
        self.localIP = self.get_ip_address('br0')
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        self.dockerstart = dockerstart.start()
        self.docker_client = docker.from_env() 
        self.container_monitor = hub.spawn(self._container_monitor)
        # {service_name: {container_name: {"last_used": timestamp, "ip": client_ip}}}
        self.container_status = {}  
        # {service_name: {client_ip: container_name}}
        self.ip_container_map = {}  
        self.CONTAINER_TIMEOUT = 300  # 5分鐘
        self.active_ssh_connections = set()  # 追踪活動的SSH連接
        self.pigrelay_active = False  # 追踪pigrelay連接狀態
        self.initialize_services()
        self.logger.info(f"Controller initialized with local IP: {self.localIP}")

    def initialize_services(self):
        """初始化所有服務的容器管理"""
        for i, (port, configs) in enumerate(self.docker_config.items()):
            service_name = configs[0].get('name', f'service_{port}')
            self.container_status[service_name] = {}
            self.ip_container_map[service_name] = {}
            
            # 檢查容器是否已經運行
            container_name = f"{service_name}0"
            existing_containers = self.docker_client.containers.list(filters={"name": container_name})
            if existing_containers:
                # 如果容器已存在，更新狀態
                self.container_status[service_name][container_name] = {
                    "last_used": datetime.now(),
                    "ip": None,
                    "is_primary": True,
                    "config": configs[0]
                }
                self.logger.info(f"Found existing container {container_name} for service {service_name}")
            else:
                self.logger.info(f"No existing container found for service {service_name}")

    def get_ip_address(self, interface_name):
        try:
            result = subprocess.run(['ip', 'addr', 'show', interface_name], 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, 
                                    text=True)
            if result.returncode != 0:
                self.logger.error(f"Error getting IP: {result.stderr.strip()}")
                return None
                
            match = re.search(r'inet\s+([\d.]+)', result.stdout)
            if match:
                self.logger.info(f"Local IP: {match.group(1)}")
                return match.group(1)
            else:
                self.logger.warning("No IP address found.")
                return None
        except Exception as e:
            self.logger.error(f"Error getting IP address: {e}")
            return None

    def _monitor(self):
        while True:
            # 清理過期的packet_store條目
            current_time = datetime.now()
            expired_packets = []
            
            for i, (pkt_hash, msg, timestamp) in enumerate(self.packet_store):
                if (current_time - timestamp).total_seconds() > 3:
                    expired_packets.append(i)
            
            # 從後往前移除，避免索引問題
            for i in sorted(expired_packets, reverse=True):
                self.packet_store.pop(i)
                
            hub.sleep(0.05)

    def _container_monitor(self):
        """監控容器使用狀況"""
        while True:
            current_time = datetime.now()
            for service_name, containers in list(self.container_status.items()):
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
                                if (current_time - status["last_used"]).total_seconds() > self.CONTAINER_TIMEOUT:
                                    self.logger.info(f"Removing inactive container {container_name}")
                                    try:
                                        container.remove(force=True)
                                    except:
                                        self.logger.error(f"Failed to remove container {container_name}")
                                    
                                    if container_name in self.container_status[service_name]:
                                        del self.container_status[service_name][container_name]
                                        
                                    if status["ip"] and status["ip"] in self.ip_container_map.get(service_name, {}):
                                        del self.ip_container_map[service_name][status["ip"]]
                    except docker.errors.NotFound:
                        # 如果容器不存在且是主要容器，重新創建
                        if status.get("is_primary", False):
                            self.logger.info(f"Recreating primary container {container_name}")
                            start_new_container(container_name, status["config"])
                    except Exception as e:
                        self.logger.error(f"Error monitoring container {container_name}: {e}")
                        
            hub.sleep(10)

    def get_available_container(self, client_ip, port):
        """為指定服務和客戶端 IP 分配容器"""
        service_name = f"port_{port}"
        if service_name not in self.container_status:
            self.logger.error(f"Unknown service for port {port}")
            return None, None
            
        # 如果該 IP 已有指定的容器
        if client_ip in self.ip_container_map.get(service_name, {}):
            container_name = self.ip_container_map[service_name][client_ip]
            if container_name in self.container_status[service_name]:
                self.update_container_timestamp(service_name, container_name)
                return container_name, self.container_status[service_name][container_name]["config"]
        
        # 檢查是否可以使用主要容器
        primary_container = f"{service_name}0"
        if primary_container in self.container_status[service_name]:
            if self.container_status[service_name][primary_container]["ip"] is None:
                self.container_status[service_name][primary_container]["ip"] = client_ip
                self.ip_container_map.setdefault(service_name, {})[client_ip] = primary_container
                self.update_container_timestamp(service_name, primary_container)
                return primary_container, self.container_status[service_name][primary_container]["config"]
        
        # 檢查服務是否支持多個容器
        service_config = self.docker_config.get(port, [{}])[0]
        if service_config.get('multi', 'no') != 'yes':
            return primary_container, service_config
            
        # 創建新的容器
        new_container_name = f"{service_name}_{len(self.container_status[service_name])}"
        if start_new_container(new_container_name, service_config):
            self.ip_container_map.setdefault(service_name, {})[client_ip] = new_container_name
            self.container_status.setdefault(service_name, {})[new_container_name] = {
                "last_used": datetime.now(),
                "ip": client_ip,
                "is_primary": False,
                "config": service_config
            }
            return new_container_name, service_config
        
        return None, None

    def update_container_timestamp(self, service_name, container_name):
        """更新容器的最後使用時間"""
        if service_name in self.container_status and container_name in self.container_status[service_name]:
            self.container_status[service_name][container_name]["last_used"] = datetime.now()
            self.logger.debug(f"Updated timestamp for container {container_name}")

    def hash_packet(self, pkt):
        """生成封包的雜湊值，用於識別和比對封包"""
        hash_parts = []
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt:
            hash_parts.append(f"{eth_pkt.src}{eth_pkt.dst}{eth_pkt.ethertype}")
            
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            hash_parts.append(f"{ipv4_pkt.src}{ipv4_pkt.dst}{ipv4_pkt.proto}{ipv4_pkt.identification}")
            
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            hash_parts.append(f"{tcp_pkt.src_port}{tcp_pkt.dst_port}{tcp_pkt.seq}{tcp_pkt.ack}")
            
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
        
        if not ipv4_pkt:
            self.logger.debug("Alert received for non-IPv4 packet")
            return
            
        # 檢查是否為針對本機的封包
        if ipv4_pkt.dst == self.localIP:
            self.logger.info(f"Alert detected for traffic to local IP: {ipv4_pkt.src} -> {ipv4_pkt.dst}")
            self.pigrelay_active = True  # 標記pigrelay已連接
            
            pkt_hash = self.hash_packet(pkt)
            if pkt_hash is None:
                self.logger.warning("Invalid packet format.")
                return
                
            self.logger.info(f"Alert packet hash: {pkt_hash}, time: {datetime.now()}")
            
            # 尋找對應的原始封包
            found = False
            for i, (stored_hash, stored_msg, timestamp) in enumerate(self.packet_store):
                if stored_hash == pkt_hash:
                    found = True
                    self.packet_store.pop(i)
                    self.logger.info(f"Matching packet found: {pkt_hash}")
                    
                    # 檢查是否為SSH流量
                    original_pkt = packet.Packet(stored_msg.data)
                    tcp_pkt = original_pkt.get_protocol(tcp.tcp)
                    
                    if tcp_pkt and tcp_pkt.dst_port == 22:
                        # 即使是警報，也保持SSH連接
                        conn_key = (ipv4_pkt.src, tcp_pkt.src_port)
                        if conn_key in self.active_ssh_connections:
                            self.logger.info(f"Maintaining SSH connection despite alert: {conn_key}")
                            # 不轉向SSH流量
                            return
                    
                    # 轉向非SSH流量到其他容器
                    self.alert_packet(original_pkt)
                    break
                    
            if not found:
                self.logger.warning(f"No matching packet found for alert: {pkt_hash}")

    def alert_packet(self, pkt):
        """將警報封包重定向到專用容器"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocol(ethernet.ethernet)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        # 確認不是SSH流量
        if tcp_pkt and tcp_pkt.dst_port == 22:
            self.logger.info(f"Not redirecting SSH traffic from alert: {ipv4_pkt.src}:{tcp_pkt.src_port}")
            return
            
        # 設置輸出目錄
        output_dir = "./other"
        os.makedirs(output_dir, exist_ok=True)
        
        # 獲取目標容器IP
        target_ip = getip.getcontainer_ip("other")
        if not target_ip:
            self.logger.error("Could not get IP for 'other' container")
            return
            
        self.logger.info(f"Redirecting alert traffic to: {target_ip}")
        
        # 創建新封包
        new_pkt = packet.Packet()
        if eth:
            new_pkt.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                src=eth.src,
                dst=eth.dst
            ))
            scapy_pkt = Ether(src=eth.src, dst=eth.dst, type=eth.ethertype)
            
        if ipv4_pkt:
            new_ip_pkt = ipv4.ipv4(
                dst=target_ip,
                src=ipv4_pkt.src,
                proto=ipv4_pkt.proto
            )
            self.logger.info(f"Redirecting traffic: {ipv4_pkt.src} -> {target_ip}")
            new_pkt.add_protocol(new_ip_pkt)
            
            if eth:
                scapy_pkt = Ether(src=eth.src, dst=eth.dst, type=eth.ethertype) / \
                             IP(src=ipv4_pkt.src, dst=target_ip, proto=ipv4_pkt.proto)
            else:
                scapy_pkt = IP(src=ipv4_pkt.src, dst=target_ip, proto=ipv4_pkt.proto)
                
        if icmp_pkt:
            new_pkt.add_protocol(icmp_pkt)
            if eth and ipv4_pkt:
                scapy_pkt = Ether(src=eth.src, dst=eth.dst, type=eth.ethertype) / \
                            IP(src=ipv4_pkt.src, dst=target_ip, proto=ipv4_pkt.proto) / \
                            ICMP(type=icmp_pkt.type, code=icmp_pkt.code)
            elif eth:
                scapy_pkt = Ether(src=eth.src, dst=eth.dst, type=eth.ethertype) / \
                            ICMP(type=icmp_pkt.type, code=icmp_pkt.code)
            elif ipv4_pkt:
                scapy_pkt = IP(src=ipv4_pkt.src, dst=target_ip, proto=ipv4_pkt.proto) / \
                            ICMP(type=icmp_pkt.type, code=icmp_pkt.code)
            else:
                scapy_pkt = ICMP(type=icmp_pkt.type, code=icmp_pkt.code)
                
        new_pkt.serialize()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = os.path.join(output_dir, f"alert_packet_{timestamp}.pcap")
        wrpcap(pcap_filename, scapy_pkt)
        self.logger.info(f"Packet saved to PCAP: {pcap_filename}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """處理交換機連接事件"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 安裝默認流表規則，將未知流量發送到控制器
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """添加流表規則"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst)
        datapath.send_msg(mod)

    def handle_service_packet(self, pkt, datapath, in_port, msg, dst_port):
        """處理服務封包"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        if not ipv4_pkt or not tcp_pkt:
            self.logger.warning("Invalid packet for service handling")
            return
            
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # 獲取服務配置
        service_config = self.docker_config.get(dst_port, [{}])[0]
        service_name = service_config.get('name', f'service_{dst_port}')
        
        # 記錄SSH連接
        if dst_port == 22:
            conn_key = (ipv4_pkt.src, tcp_pkt.src_port)
            self.active_ssh_connections.add(conn_key)
            self.logger.info(f"Added SSH connection to tracking: {conn_key}")
            
            # 如果pigrelay已連接，對SSH流量特殊處理
            if self.pigrelay_active:
                self.logger.info(f"pigrelay active, ensuring SSH traffic is maintained")
        
        # 獲取容器名稱
        container_name = f"{service_name}0"  # 使用主要容器
        
        # 更新使用時間
        if service_name in self.container_status and container_name in self.container_status[service_name]:
            self.container_status[service_name][container_name]["last_used"] = datetime.now()
            
        # 更新客戶端IP與容器對應關係
        if service_name not in self.ip_container_map:
            self.ip_container_map[service_name] = {}
            
        self.ip_container_map[service_name][ipv4_pkt.src] = container_name
        
        if service_name not in self.container_status:
            self.container_status[service_name] = {}
            
        if container_name not in self.container_status[service_name]:
            self.container_status[service_name][container_name] = {
                "last_used": datetime.now(),
                "ip": ipv4_pkt.src,
                "is_primary": True,
                "config": service_config
            }
        else:
            self.container_status[service_name][container_name]["ip"] = ipv4_pkt.src
            
        # 獲取容器 IP
        target_ip = getip.getcontainer_ip(container_name)
        if not target_ip:
            self.logger.error(f"Could not get IP for container {container_name}")
            return
            
        # 設置目標端口
        target_port = service_config.get('target_port', dst_port)
        
        # 建立連接映射雙向存儲連接信息
        conn_key_forward = (ipv4_pkt.src, tcp_pkt.src_port)
        conn_key_reverse = (target_ip, target_port)
        
        self.connection_map[conn_key_forward] = (target_ip, target_port)
        self.connection_map[conn_key_reverse] = (ipv4_pkt.src, tcp_pkt.src_port)
        
        # 記錄服務類型
        self.service_connections[conn_key_forward] = service_name
        
        # 保存IP對應關係
        self.connection_ip[ipv4_pkt.src] = target_ip
        self.connection_ip[target_ip] = ipv4_pkt.src
        
        self.logger.info(f"Traffic on port {dst_port}: {ipv4_pkt.src}:{tcp_pkt.src_port} -> "
                         f"{target_ip}:{target_port} (Container: {container_name})")
        
        # 確保流量可雙向對應
        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(tcp_dst=target_port),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        
        # 添加雙向流規則
        match_forward = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_TCP,
            ipv4_src=ipv4_pkt.src,
            ipv4_dst=ipv4_pkt.dst,
            tcp_src=tcp_pkt.src_port,
            tcp_dst=tcp_pkt.dst_port
        )
        
        self.add_flow(datapath, 2, match_forward, actions)
        
        # 返回方向的流規則
        match_reverse = parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=inet.IPPROTO_TCP,
            ipv4_src=target_ip,
            tcp_src=target_port
        )
        
        actions_reverse = [
            parser.OFPActionSetField(ipv4_src=ipv4_pkt.dst),  # 原始目標IP
            parser.OFPActionSetField(tcp_src=tcp_pkt.dst_port),  # 原始目標端口
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        
        self.add_flow(datapath, 2, match_reverse, actions_reverse)
        
        # 發送封包
        out = parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=msg.buffer_id,
            in_port=in_port, 
            actions=actions, 
            data=msg.data
        )
        
        datapath.send_msg(out)

    def return_packet(self, pkt, datapath, in_port, msg):
        """處理從容器返回的封包"""
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        if not ipv4_pkt or not tcp_pkt:
            self.logger.debug("Invalid return packet")
            return
            
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # 使用IP+端口組合作為查詢鍵
        conn_key = (ipv4_pkt.src, tcp_pkt.src_port)
        original_dst = self.connection_map.get(conn_key)
        
        if not original_dst and ipv4_pkt.src in self.connection_ip:
            # 嘗試僅通過IP查找
            original_client_ip = self.connection_ip[ipv4_pkt.src]
            self.logger.info(f"Fallback to IP-only mapping: {ipv4_pkt.src} -> {original_client_ip}")
            
            actions = [
                parser.OFPActionSetField(ipv4_dst=original_client_ip),
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
            return
            
        self.logger.info(f"Incoming redirected traffic: {ipv4_pkt.src}:{tcp_pkt.src_port} -> "
                        f"{ipv4_pkt.dst}:{tcp_pkt.dst_port}")
                        
        if original_dst:
            original_dst_ip, original_dst_port = original_dst
            self.logger.info(f"Routing back to: {original_dst_ip}:{original_dst_port}")
            
            actions = [
                parser.OFPActionSetField(ipv4_dst=original_dst_ip),
                parser.OFPActionSetField(tcp_dst=original_dst_port),
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """處理封包進入事件"""
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        # 處理TCP流量
        if ipv4_pkt and tcp_pkt:
            # 檢查是否為SSH流量 (目標端口22)
            if tcp_pkt.dst_port == 22 and ipv4_pkt.dst == self.localIP:
                # 儲存SSH連線信息
                conn_key = (ipv4_pkt.src, tcp_pkt.src_port)
                self.active_ssh_connections.add(conn_key)
                
                # 存儲封包用於比對警報
                pkt_hash = self.hash_packet(pkt)
                if pkt_hash:
                    self.packet_store.append((pkt_hash, msg, datetime.now()))
                    
                self.handle_service_packet(pkt, datapath, in_port, msg, tcp_pkt.dst_port)
                return
                
            # 檢查從容器返回的流量
            if tcp_pkt.src_port in [2222, 2223]:
                self.return_packet(pkt, datapath, in_port, msg)
                return
                
            # 檢查任何連接映射對應的返回流量
            conn_key = (ipv4_pkt.src, tcp_pkt.src_port)
            if conn_key in self.connection_map:
                self.return_packet(pkt, datapath, in_port, msg)
                return
                
        # 檢查Snort相關流量
        if ipv4_pkt and self.snort.getsnortip():
            if ipv4_pkt.dst == self.snort.getsnortip() or ipv4_pkt.src == self.snort.getsnortip():
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
                
        # 保存封包用於比對警報
        if ipv4_pkt and ipv4_pkt.dst == self.localIP:
            pkt_hash = self.hash_packet(pkt)
            if pkt_hash:
                current_time = datetime.now()
                self.packet_store.append((pkt_hash, msg, current_time))
            return
            
        # 一般封包處理 (MAC學習等)
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
        
    

        '''
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        '''

