from datetime import datetime


# format datetime for readable incident reports
def format_time(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S %Z")


# legacy human-readable narratives for port scans
def generate_narrative(port_scans: list[dict]) -> list[str]:
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


# narratives for DNS query activity
def generate_dns_narrative(dns_events: list[dict]) -> list[str]:
    narratives = []

    if dns_events:
        narratives.append(
            f"DNS activity was observed involving {len(dns_events)} queries, "
            f"which may indicate host discovery or external communication."
        )

    return narratives


# analyst-friendly narratives for port scans
def generate_port_scan_narrative(scans: list[dict]) -> list[str]:
    narratives = []

    for scan in scans:
        mitre = scan.get("mitre", {})
        start_time = format_time(scan["start_time"]) if isinstance(scan.get("start_time"), datetime) else scan.get("start_time")
        end_time = format_time(scan["end_time"]) if isinstance(scan.get("end_time"), datetime) else scan.get("end_time")

        narrative = (
            "[Reconnaissance Detected]\n\n"
            f"Source Host      : {scan.get('src_ip')}\n"
            f"Target Host      : {scan.get('dst_ip')}\n"
            f"Time Window      : {start_time} – {end_time}\n"
            f"Ports Probed     : {', '.join(map(str, scan.get('ports', [])))}\n\n"
            "MITRE ATT&CK\n"
            f"  Tactic         : {mitre.get('tactic', 'N/A')}\n"
            f"  Technique      : {mitre.get('technique', 'N/A')} ({mitre.get('technique_id', 'N/A')})\n\n"
            "Assessment       : Activity is consistent with network reconnaissance."
        )
        narratives.append(narrative)

    return narratives


# analyst-friendly narratives for suspicious UDP activity
def generate_udp_activity_narrative(udp_events: list[dict]) -> list[str]:
    narratives = []

    for event in udp_events:
        start = format_time(event["start_time"]) if isinstance(event.get("start_time"), datetime) else event.get("start_time")
        end = format_time(event["end_time"]) if isinstance(event.get("end_time"), datetime) else event.get("end_time")
        ports = ", ".join(str(p) for p in event.get("ports", []))

        narrative = (
            "[Suspicious UDP Activity Detected]\n\n"
            f"Source Host      : {event.get('src_ip')}\n"
            f"Target Host      : {event.get('dst_ip')}\n"
            f"Time Window      : {start} – {end}\n"
            f"Ports Targeted   : {ports}\n"
            "Assessment       : High-volume or multi-port UDP activity was "
            "observed. This may indicate service probing, discovery activity, "
            "or protocol abuse."
        )
        narratives.append(narrative)

    return narratives


# narratives for ICMP host discovery activity
def generate_icmp_narrative(icmp_events: list[dict]) -> list[str]:
    narratives = []

    for e in icmp_events:
        mitre = e.get("mitre", {})

        narrative = (
            "[ICMP Host Discovery Detected]\n\n"
            f"Source Host      : {e.get('src_ip')}\n"
            f"Targets          : {', '.join(e.get('targets', []))}\n"
            f"Total Hosts      : {e.get('count')}\n\n"
            "MITRE ATT&CK\n"
            f"  Tactic         : {mitre.get('tactic', 'N/A')}\n"
            f"  Technique      : {mitre.get('technique', 'N/A')} ({mitre.get('technique_id', 'N/A')})\n\n"
            "Assessment       : Multiple ICMP echo requests indicate host discovery."
        )
        narratives.append(narrative)

    return narratives