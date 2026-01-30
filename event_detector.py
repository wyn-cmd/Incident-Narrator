from collections import defaultdict
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP
from mitre_mapping import MITRE_TECHNIQUES

def detect_port_scans(events, threshold=3):
    scans = defaultdict(lambda: {
        "ports": set(),
        "times": []
    })

    for e in events:
        if e.get("protocol") != "TCP" or not e.get("dst_port"):
            continue

        key = (e["src_ip"], e["dst_ip"])
        scans[key]["ports"].add(e["dst_port"])
        scans[key]["times"].append(e["time"])

    results = []
    for (src_ip, dst_ip), data in scans.items():
        if len(data["ports"]) >= threshold:
            results.append({
                "type": "Port Scan",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ports": sorted(data["ports"]),
                "start_time": min(data["times"]),
                "end_time": max(data["times"]),
                "mitre": MITRE_TECHNIQUES["TCP_PORT_SCAN"],
            })

    return results



def detect_dns_activity(events):
    dns_queries = []

    for e in events:
        if (
            e.get("protocol") == "UDP"
            and e.get("dst_port") == 53
            and e.get("src_ip")
            and e.get("dst_ip")
        ):
            dns_queries.append({
                "time": e["time"],
                "src_ip": e["src_ip"],
                "dst_ip": e["dst_ip"]
            })

    return dns_queries


def detect_udp_activity(events, threshold=5):
    
    # Detect suspicious UDP probing or scanning behavior.
    
    udp_tracker = defaultdict(lambda: {
        "ports": set(),
        "timestamps": []
    })

    for e in events:
        if e.get("protocol") != "UDP" or not e.get("dst_port"):
            continue

        key = (e["src_ip"], e["dst_ip"])
        udp_tracker[key]["ports"].add(e["dst_port"])
        udp_tracker[key]["timestamps"].append(e["time"])

    detections = []
    for (src_ip, dst_ip), data in udp_tracker.items():
        if len(data["ports"]) >= threshold:
            detections.append({
                "type": "UDP Activity",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ports": sorted(data["ports"]),
                "start_time": min(data["timestamps"]),
                "end_time": max(data["timestamps"]),
                "mitre": MITRE_TECHNIQUES["UDP_PROBING"],
            })

    return detections


def detect_icmp_discovery(events):
    # detect ICMP host discovery activity like ping sweeps

    # key is the source IP, values is a list of destination IPs
    icmp_tracker = defaultdict(list)  

    for e in events:
        # Only consider ICMP packets
        if e.get("protocol") != "ICMP":
            continue

        # ICMP Echo Requests
        if e.get("icmp_type") == 8 and e.get("src_ip") and e.get("dst_ip"):
            icmp_tracker[e["src_ip"]].append(e["dst_ip"])

    detections = []
    for src_ip, dst_ips in icmp_tracker.items():
        
        # threshold: > 1 host pinged 
        if len(set(dst_ips)) > 1:
            detections.append({
                "type": "ICMP Host Discovery",
                "src_ip": src_ip,
                "targets": list(set(dst_ips)), 
                "count": len(dst_ips),
                "mitre": MITRE_TECHNIQUES["ICMP_DISCOVERY"],
            })



    return detections



