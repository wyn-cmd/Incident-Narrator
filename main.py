from pcap_parser import parse_pcap
from event_detector import detect_port_scans, detect_dns_activity, detect_udp_activity
from timeline_builder import build_timeline
from narrative_generator import generate_narrative
from narrative_generator import generate_dns_narrative
from narrative_generator import generate_port_scan_narrative
from narrative_generator import generate_udp_activity_narrative



def main():
    pcap_file = "capture.pcap"

    events = parse_pcap(pcap_file)
    timeline = build_timeline(events)
    
    tcp_scans = detect_port_scans(events)
    udp_activity = detect_udp_activity(events)

    dns_events = detect_dns_activity(events)


    narrative = []
    narrative.extend(generate_port_scan_narrative(tcp_scans))
    narrative.extend(generate_udp_activity_narrative(udp_activity))
    narrative.extend(generate_dns_narrative(dns_events))

    print("\n" + "=" * 60)
    print("INCIDENT NARRATIVE REPORT")
    print("=" * 60 + "\n")

    if not narrative:
        print(
            "[No Malicious Activity Detected]\n\n"
            "The analyzed PCAP did not contain behavior that exceeded the\n"
            "current detection thresholds. Traffic appears benign based on\n"
            "available heuristics."
        )
    else:
        for entry in narrative:
            print(entry)
            print("\n" + "-" * 60 + "\n")

if __name__ == "__main__":
    main()