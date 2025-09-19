from scapy.all import Ether, ARP, IP, IPv6, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind, ASN1F_OID
from scapy.layers.dot11 import *
from scapy.all import fragment

AVAILABLE_PROTOCOLS = {"Ethernet": Ether, "ARP": ARP, "IP": IP, "IPv6": IPv6, "TCP": TCP, "UDP": UDP, "ICMP": ICMP, "DNS": DNS, "Raw": Raw}
PACKET_TEMPLATES = {
    "ICMP Ping (google.com)": [IP(dst="8.8.8.8"), ICMP()],
    "DNS Query (google.com)": [IP(dst="8.8.8.8"), UDP(dport=53), DNS(rd=1, qd=DNSQR(qname="google.com"))],
    "TCP SYN (localhost:80)": [IP(dst="127.0.0.1"), TCP(dport=80, flags="S")],
    "ARP Request (who-has 192.168.1.1)": [Ether(dst="ff:ff:ff:ff:ff:ff"), ARP(pdst="192.168.1.1")],
    "NTP Query (pool.ntp.org)": [IP(dst="pool.ntp.org"), UDP(sport=123, dport=123), NTP()],
    "SNMP GetRequest (public)": [IP(dst="127.0.0.1"), UDP(), SNMP(community="public", PDU=SNMPget(varbindlist=[SNMPvarbind(oid='1.3.6.1.2.1.1.1.0')]))]
}
FIREWALL_PROBES = {
    "Standard SYN Scan (Top Ports)": [(lambda t: IP(dst=t)/TCP(dport=p, flags="S"), f"TCP SYN to port {p}") for p in [21, 22, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]],
    "Stealthy Scans (FIN, Xmas, Null)": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="F"), f"FIN Scan to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="FPU"), f"Xmas Scan to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags=""), f"Null Scan to port {p}") for p in [80, 443]
    ],
    "ACK Scan (Firewall Detection)": [(lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="A"), f"ACK Scan to port {p}") for p in [22, 80, 443]],
    "Source Port Evasion (DNS)": [(lambda t, p=p: IP(dst=t)/TCP(sport=53, dport=p, flags="S"), f"SYN from port 53 to {p}") for p in [80, 443, 8080]],
    "Fragmented SYN Scan": [(lambda t, p=p: fragment(IP(dst=t)/TCP(dport=p, flags="S")), f"Fragmented SYN to port {p}") for p in [80, 443]],
    "TCP Options Probes (WScale, TS)": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="S", options=[('WScale', 10), ('Timestamp', (12345, 0))]), f"SYN+WScale+TS to port {p}") for p in [80, 443]
    ],
    "ECN Flag Probes": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="SE"), f"SYN+ECE to port {p}") for p in [80, 443]
    ] + [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="SC"), f"SYN+CWR to port {p}") for p in [80, 443]
    ],
    "HTTP Payload Probe": [
        (lambda t, p=p: IP(dst=t)/TCP(dport=p, flags="PA")/Raw(load="GET / HTTP/1.0\r\n\r\n"), f"HTTP GET probe to port {p}") for p in [80, 8080, 443]
    ],
    "Common UDP Probes": [(lambda t, p=p: IP(dst=t)/UDP(dport=p), f"UDP Probe to port {p}") for p in [53, 123, 161]],
    "ICMP Probes (Advanced)": [
        (lambda t: IP(dst=t)/ICMP(type=ty), f"ICMP Echo Request (Type 8)") for ty in [8]
    ] + [
        (lambda t: IP(dst=t)/ICMP(type=ty), f"ICMP Timestamp Request (Type 13)") for ty in [13]
    ] + [
        (lambda t: IP(dst=t)/ICMP(type=ty), f"ICMP Address Mask Request (Type 17)") for ty in [17]
    ]
}
SCAN_TYPES = ["TCP SYN Scan", "TCP FIN Scan", "TCP Xmas Scan", "TCP Null Scan", "TCP ACK Scan", "UDP Scan"]
COMMON_FILTERS = [
    "", "tcp", "udp", "arp", "icmp",
    "port 80", "port 443", "udp port 53", "tcp port 22",
    "host 8.8.8.8", "net 192.168.1.0/24", "vlan"
]

COMMUNITY_TOOLS = {
    "Interpreters and REPLs": [
        ("scapy-console", "https://github.com/gpotter2/scapy-console", "A Scapy console with many other tools and features."),
        ("Scapy REPL", "https://github.com/GabrielCama/scapy-repl", "An interactive Scapy REPL with customized commands.")
    ],
    "Networking": [
        ("bettercap", "https://github.com/bettercap/bettercap", "A powerful, flexible and portable tool for network attacks and monitoring."),
        ("Routersploit", "https://github.com/threat9/routersploit", "An open-source exploitation framework dedicated to embedded devices."),
        ("Batfish", "https://www.batfish.org/", "A network configuration analysis tool for validating and verifying network designs.")
    ],
    "Network Scanners & Analyzers": [
        ("Wireshark", "https://www.wireshark.org/", "The world's foremost and widely-used network protocol analyzer."),
        ("Nmap", "https://nmap.org/", "The Network Mapper - a free and open source utility for network discovery and security auditing."),
        ("Zeek", "https://zeek.org/", "A powerful network analysis framework that is much different from a typical IDS."),
        ("BruteShark", "https://github.com/odedshimon/BruteShark", "An open-source, cross-platform network forensic analysis tool (NFAT).")
    ],
    "Wireless": [
        ("Kismet", "https://www.kismetwireless.net/", "A wireless network detector, sniffer, and intrusion detection system."),
        ("Airgeddon", "https://github.com/v1s1t0r1sh3r3/airgeddon", "A multi-use bash script for Linux systems to audit wireless networks."),
        ("wifiphisher", "https://github.com/wifiphisher/wifisher", "A rogue Access Point framework for conducting red team engagements or Wi-Fi security testing."),
        ("Wifite2", "https://github.com/derv82/wifite2", "A complete rewrite of the popular wireless network auditing tool, wifite.")
    ],
    "Password Cracking": [
        ("John the Ripper", "https://www.openwall.com/john/", "A fast password cracker, available for many operating systems."),
        ("Hashcat", "https://hashcat.net/hashcat/", "The world's fastest and most advanced password recovery utility."),
        ("hcxtools", "https://github.com/ZerBea/hcxtools", "Tools to convert Wi-Fi captures into hash formats for Hashcat or John.")
    ],
    "Web & API Security": [
        ("reNgine", "https://github.com/yogeshojha/rengine", "An automated reconnaissance framework for web applications."),
        ("Astra", "https://github.com/flipkart-incubator/Astra", "Automated Security Testing For REST APIs.")
    ],
    "Industrial Control Systems (ICS)": [
        ("Scapy-cip-enip", "https://github.com/scapy-cip/scapy-cip-enip", "An EtherNet/IP and CIP implementation for Scapy."),
        ("Scapy-dnp3", "https://github.com/scapy-dnp3/scapy-dnp3", "A DNP3 implementation for Scapy."),
        ("Scapy-modbus", "https://github.com/scapy-modbus/scapy-modbus", "A Modbus implementation for Scapy.")
    ]
}
