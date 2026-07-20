#!/usr/bin/env python3
"""
Basic Network Sniffer
----------------------
Captures live network packets and displays:
- Source / Destination IP addressesS
- Protocol (TCP/UDP/ICMP/etc.)
- Source/Destination Ports
- Payload data (if present)

Requirements:
    pip install scapy

Run with administrator/root privileges:
    sudo python3 network_sniffer.py      (Linux/Mac)
    python network_sniffer.py            (Windows, run as Admin)
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
from datetime import datetime

packet_count = 0


def get_protocol_name(packet):
    """Return protocol name based on packet content."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def process_packet(packet):
    """Callback executed for every captured packet."""
    global packet_count

    if packet.haslayer(IP):
        packet_count += 1
        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = get_protocol_name(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")

        print("=" * 70)
        print(f"[{packet_count}] Time: {timestamp}")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        if packet.haslayer(TCP):
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Dest Port      : {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Dest Port      : {packet[UDP].dport}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded = payload.decode(errors="replace")
                print(f"Payload        : {decoded[:100]}")
            except Exception:
                print(f"Payload (raw)  : {payload[:100]}")

        print("=" * 70 + "\n")


def start_sniffer(interface=None, packet_count_limit=50):
    """Start capturing packets on the given interface."""
    print("Starting Network Sniffer... (Press Ctrl+C to stop)\n")
    print("[*] Using Layer 3 socket (no Npcap/WinPcap required)\n")

    # Use L3 socket (raw IP socket) since Npcap/WinPcap is not installed
    socket = conf.L3socket(iface=interface)

    sniff(
        opened_socket=socket,
        prn=process_packet,
        count=packet_count_limit,
        store=False
    )


if __name__ == "__main__":
    # interface=None -> default interface
    # packet_count_limit=0 -> unlimited capture until Ctrl+C
    start_sniffer(interface=None, packet_count_limit=50)

