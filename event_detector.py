from collections import defaultdict
from scapy.layers.dns import DNS

def detect_port_scans(events, threshold=3):
    scans = defaultdict(lambda: {
        "ports": set(),
        "times": []
    })

    for e in events:
        if (
            e.get("protocol") != "TCP"
            or not e.get("dst_port")
            or not e.get("src_ip")
            or not e.get("dst_ip")
        ):
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


def detect_udp_activity(events: list[dict], threshold: int = 5) -> list[dict]:
    
    # Detect suspicious UDP probing or scanning behavior.
    
    udp_tracker = defaultdict(lambda: {
        "ports": set(),
        "timestamps": []
    })

    for event in events:
        for event in events:
            if (
                event.get("protocol") != "UDP"
                or not event.get("dst_port")
                or not event.get("src_ip")
                or not event.get("dst_ip")
            ):

                continue

        if event["protocol"] != "UDP" or not event["dst_port"]:
            continue

        key = (event["src_ip"], event["dst_ip"])
        udp_tracker[key]["ports"].add(event["dst_port"])
        udp_tracker[key]["timestamps"].append(event["time"])

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
            })

    return detections



