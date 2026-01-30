from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime


def parse_pcap(pcap_file):
    # load packets from PCAP file for parsing
    packets = rdpcap(pcap_file)
    events = []

    for pkt in packets:
        if IP in pkt:
            event = {
                "time": datetime.fromtimestamp(float(pkt.time)),
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "protocol": "OTHER",
                "src_port": None,
                "dst_port": None,
                "length": len(pkt)
            }

            if TCP in pkt:
                event["protocol"] = "TCP"
                event["src_port"] = pkt[TCP].sport
                event["dst_port"] = pkt[TCP].dport

            elif UDP in pkt:
                event["protocol"] = "UDP"
                event["src_port"] = pkt[UDP].sport
                event["dst_port"] = pkt[UDP].dport

            events.append(event)

    return events