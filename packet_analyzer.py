
from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv
import os
from datetime import datetime

filename = "network_traffic.csv"

headers = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "tcp_flags"
]

# Create the CSV only if it does not exist
if not os.path.exists(filename) or os.path.getsize(filename) == 0:
    with open(filename, "w", newline="") as file:
        csv.writer(file).writerow(headers)


def analyze_packet(packet):

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    size = len(packet)

    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    tcp_flags = "NONE"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    timestamp = datetime.now().isoformat()

    with open(filename, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            src,
            dst,
            protocol,
            src_port,
            dst_port,
            size,
            tcp_flags
        ])

    print(
        src, "->", dst,
        protocol,
        "Size:", size,
        "TCP Flags:", tcp_flags
    )


print("Network monitoring started...")
print("Interface: enp0s8")
print("Capturing TCP flags...")
print("Saving packets to:", filename)

sniff(
    iface="enp0s8",
    prn=analyze_packet,
    store=False
)

