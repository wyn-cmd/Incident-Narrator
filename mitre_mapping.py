
# MITRE ATT&CK technique mappings for the incident narrator

MITRE_TECHNIQUES = {
    "TCP_PORT_SCAN": {
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
    },
    "UDP_PROBING": {
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
    },
    "ICMP_DISCOVERY": {
        "tactic": "Reconnaissance",
        "technique_id": "T1018",
        "technique": "Remote System Discovery",
    },
    "DNS_ACTIVITY": {
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique": "DNS",
    },
}