
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import joblib
import csv
import os
from datetime import datetime

print("Loading trained AI-NIDS model...")
model = joblib.load("nids_model.pkl")
filename = "alerts.csv"

headers = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "tcp_flags",
    "detection_result"
]

  # Create a fresh alerts file with the current column structure
with open(filename, "w", newline="") as file:
    csv.writer(file).writerow(headers)

protocol_map = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "OTHER": 0
}


def detect_packet(packet):

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

    # Convert TCP flags into numerical features
    flags = tcp_flags

    features = pd.DataFrame([{
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_size": size,
        "protocol": protocol_map.get(protocol, 0),
        "tcp_syn": int("S" in flags),
        "tcp_ack": int("A" in flags),
        "tcp_fin": int("F" in flags),
        "tcp_rst": int("R" in flags),
        "tcp_psh": int("P" in flags),
        "tcp_urg": int("U" in flags),
        "tcp_ece": int("E" in flags),
        "tcp_cwr": int("C" in flags)
    }])

    # AI prediction
    prediction = model.predict(features)[0]

    if prediction == -1:
        result = "ANOMALOUS"
        print("🚨 AI ALERT:", src, "->", dst, protocol,
              "Ports:", src_port, "->", dst_port,
              "Size:", size, "Flags:", tcp_flags)
    else:
        result = "NORMAL"
        print("NORMAL TRAFFIC:", src, "->", dst, protocol,
              "Size:", size, "Flags:", tcp_flags)

    timestamp = datetime.now().isoformat()

    with open(filename, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp, src, dst, protocol,
            src_port, dst_port, size,
            tcp_flags, result
        ])


print("AI-powered Network Intrusion Detection System started!")
print("Monitoring interface: enp0s8")
print("Press CTRL+C to stop monitoring.")

sniff(
    iface="enp0s8",
    prn=detect_packet,
    store=False
)

