def generate_narrative(port_scans):

    # generate human-readable narratives for detected port scans
    
    narrative = []

    for scan in port_scans:
        text = (
            f"Between {scan['start_time']} & {scan['end_time']}, "
            f"the host {scan['src']} conducted a reconnaissance scan against "
            f"{scan['dst']}, probing the following ports: {scan['ports']}. "
            f"This behavior is consistent with network reconnaissance activity."
        )
        narrative.append(text)

    return narrative

def generate_dns_narrative(dns_events):
    narrative = []

    if dns_events:
        narrative.append(
            f"DNS activity was observed involving {len(dns_events)} queries, "
            f"which may indicate host discovery or external communication."
        )

    return narrative

def format_time(dt):
    
    # Format datetime for readable incident reports.

    return dt.strftime("%H:%M:%S %Z")


def generate_port_scan_narrative(scans: list[dict]) -> list[str]:
    
    # Generate well-formatted, analyst-friendly narratives for port scans.

    narratives = []

    for scan in scans:
        src_ip = scan["src_ip"]
        dst_ip = scan["dst_ip"]

        start = format_time(scan["start_time"])
        end = format_time(scan["end_time"])
        ports = ", ".join(str(p) for p in scan["ports"])

        narrative = (
            "[Reconnaissance Detected]\n\n"
            f"Source Host      : {src_ip}\n"
            f"Target Host      : {dst_ip}\n"
            f"Time Window      : {start} – {end}\n"
            f"Ports Probed     : {ports}\n"
            "Assessment       : Behavior is consistent with TCP port scanning "
            "activity."
        )

        narratives.append(narrative)

    return narratives


def generate_udp_activity_narrative(udp_events: list[dict]) -> list[str]:
    
    # Generate analyst-friendly narratives for suspicious UDP activity.
    
    narratives = []

    for event in udp_events:
        start = format_time(event["start_time"])
        end = format_time(event["end_time"])
        ports = ", ".join(str(p) for p in event["ports"])

        narrative = (
            "[Suspicious UDP Activity Detected]\n\n"
            f"Source Host      : {event['src_ip']}\n"
            f"Target Host      : {event['dst_ip']}\n"
            f"Time Window      : {start} – {end}\n"
            f"Ports Targeted   : {ports}\n"
            "Assessment       : High-volume or multi-port UDP activity was "
            "observed. This may indicate service probing, discovery activity, "
            "or protocol abuse."
        )

        narratives.append(narrative)

    return narratives



def generate_icmp_narrative(icmp_events: list[dict]) -> list[str]:

    # Generate narratives for ICMP host discovery activity
    
    narratives = []

    for event in icmp_events:
        targets = ", ".join(event["targets"])
        narrative = (
            "[ICMP Host Discovery Detected]\n\n"
            f"Source Host  : {event['src_ip']}\n"
            f"Targets      : {targets}\n"
            f"Total Hosts  : {event['count']}\n"
            "Assessment   : Multiple hosts were pinged by this source, "
            "indicating potential network reconnaissance activity."
        )
        narratives.append(narrative)

    return narratives
