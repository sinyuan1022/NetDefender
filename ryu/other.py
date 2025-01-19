from scapy.all import Ether, IP, ICMP, wrpcap
from datetime import datetime
import os


def alert_packet(self, pkt, datapath, in_port, msg):
    ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
    tcp_pkt = pkt.get_protocol(tcp.tcp)
    eth = pkt.get_protocol(ethernet.ethernet)
    icmp_pkt = pkt.get_protocol(icmp.icmp)

    # 本地 other 資料夾
    output_dir = "./other"
    os.makedirs(output_dir, exist_ok=True)  # 如果資料夾不存在則自動建立

    target_ip = getip.getcontainer_ip("other")

    if tcp_pkt:
        target_port = tcp_pkt.dst_port
        self.logger.info("Outgoing SSH traffic: %s:%s -> %s:%s",
                         ipv4_pkt.src, tcp_pkt.src_port,
                         ipv4_pkt.dst, tcp_pkt.dst_port)
    else:
        # Create a new packet
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

        # Convert Ryu packet to Scapy packet for saving as PCAP
        scapy_pkt = Ether(src=eth.src, dst=eth.dst, type=eth.ethertype) / \
                    IP(src=ipv4_pkt.src, dst=target_ip, proto=ipv4_pkt.proto) / \
                    ICMP(type=icmp_pkt.type, code=icmp_pkt.code)

        # Generate PCAP file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = os.path.join(output_dir, f"alert_packet_{timestamp}.pcap")
        wrpcap(pcap_filename, scapy_pkt)

        self.logger.info(f"Packet saved to PCAP: {pcap_filename}")