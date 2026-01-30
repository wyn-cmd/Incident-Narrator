from scapy.all import rdpcap
from scapy.all import IP
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import ICMP
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

            # TCP
            if TCP in pkt:
                event["protocol"] = "TCP"
                event["src_port"] = pkt[TCP].sport
                event["dst_port"] = pkt[TCP].dport

            # UDP
            elif UDP in pkt:
                event["protocol"] = "UDP"
                event["src_port"] = pkt[UDP].sport
                event["dst_port"] = pkt[UDP].dport

            # ICMP
            elif ICMP in pkt:
                event["protocol"] = "ICMP"
                event["icmp_type"] = pkt[ICMP].type
                event["icmp_code"] = pkt[ICMP].code

            events.append(event)

    return events
