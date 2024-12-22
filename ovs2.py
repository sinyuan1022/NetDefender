from __future__ import print_function

import array
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
from ryu.ofproto import ether, inet
from ryu.lib import hub
from datetime import datetime
import hashlib
import subprocess
import re
import readconfig as rc
import getip 



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



    def get_ip_address(self,interface_name):
        try:
            result = subprocess.run(['ip', 'addr', 'show', interface_name],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
                pkt_hash, msg, timestamp = self.packet_store.pop()
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
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)

                
                # , parser.OFPActionOutput(self.snort_port)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
            hub.sleep(0.05)

    def hash_packet(self,pkt):
        hash_parts = []

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt:
            hash_parts.append(f"{eth_pkt.src}-{eth_pkt.dst}-{eth_pkt.ethertype}")

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            hash_parts.append(f"{ipv4_pkt.src}-{ipv4_pkt.dst}-{ipv4_pkt.proto}-{ipv4_pkt.identification}")

        if not hash_parts:
            return None

        combined_key = "|".join(hash_parts)
        return hashlib.md5(combined_key.encode()).hexdigest()


    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.pkt)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if (ipv4_pkt and ipv4_pkt.dst == self.localIP):
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
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    self.alert_packet(pkt, datapath, in_port, stored_pkt)
                    return


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

    def alert_packet(self, pkt, datapath, in_port, msg):
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        eth = pkt.get_protocol(ethernet.ethernet)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        target_ip = getip.getcontainer_ip("other")
        if tcp_pkt:
            target_port = tcp_pkt.dst_port
            self.logger.info("Outgoing SSH traffic: %s:%s -> %s:%s", 
                            ipv4_pkt.src, tcp_pkt.src_port, 
                            ipv4_pkt.dst, tcp_pkt.dst_port)
        else:
            new_ip_pkt = ipv4.ipv4(
            dst=target_ip,
            src=ipv4_pkt.src,
            proto=ipv4_pkt.proto
            )
            new_pkt = packet.Packet()
            new_pkt.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                src=eth.src,
                dst=eth.dst
            ))
            new_pkt.add_protocol(new_ip_pkt)
            new_pkt.add_protocol(icmp_pkt)
            new_pkt.serialize()

            self.logger.info("Outgoing SSH traffic: %s -> %s", 
                            ipv4_pkt.src, ipv4_pkt.dst)
            self.logger.info("Redirecting to: %s", target_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=msg.match['in_port'],
                actions=actions,
                data=new_pkt.data
            )
            datapath.send_msg(out)
            return
        
        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(tcp_dst=target_port),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        self.logger.info("Redirecting to: %s:%s", target_ip, target_port)
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(out)

    def ssh_packet(self, pkt, datapath, in_port, msg):
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        target_ip = getip.getcontainer_ip("ssh1")
        target_port = self.docker_config[22]['target_port']
        self.connection_map[(ipv4_pkt.src, tcp_pkt.src_port)] = (ipv4_pkt.dst, tcp_pkt.dst_port)
        self.logger.info("Outgoing SSH traffic: %s:%s -> %s:%s", 
                        ipv4_pkt.src, tcp_pkt.src_port, 
                        ipv4_pkt.dst, tcp_pkt.dst_port)
        actions = [
            parser.OFPActionSetField(ipv4_dst=target_ip),
            parser.OFPActionSetField(tcp_dst=target_port),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        self.logger.info("Redirecting to: %s:%s", target_ip, target_port)
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(out)
        
    def return_ssh_packet(self, pkt, datapath, in_port, msg):
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
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
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=msg.data
            )
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            if tcp_pkt.dst_port == 22 and ipv4_pkt.dst == self.localIP:
                self.ssh_packet(pkt, datapath, in_port, msg)
                return
            if tcp_pkt.src_port == 2222 or tcp_pkt.src_port == 2223:
                self.return_ssh_packet(pkt, datapath, in_port, msg)
                return
        if ipv4_pkt:
            if ipv4_pkt.dst == "192.168.254.134" or ipv4_pkt.src == "192.168.254.134":
                datapath = msg.datapath
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
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return
            if (ipv4_pkt.dst == self.localIP):
                pkt_hash = self.hash_packet(pkt)
                current_time = datetime.now()
                if pkt_hash is None:
                    return
                self.packet_store.append((pkt_hash, msg, current_time))
                return

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
        # , parser.OFPActionOutput(self.snort_port)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        '''
        
        '''
        
    

        '''
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        '''

