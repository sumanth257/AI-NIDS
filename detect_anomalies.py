
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import joblib
import csv
import os
import time
from datetime import datetime
from collections import defaultdict, deque

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
    "ai_result",
    "rule_result",
    "detection_result"
]

# Create a fresh alerts file
with open(filename, "w", newline="") as file:
    csv.writer(file).writerow(headers)

protocol_map = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "OTHER": 0
}

# SYN scan tracking
scan_tracker = defaultdict(deque)
last_scan_alert = {}

WINDOW_SECONDS = 10
PORT_THRESHOLD = 10
ALERT_COOLDOWN = 10


def check_port_scan(src, dst, dst_port, tcp_flags):
    current_time = time.time()

    # Only consider initial SYN packets, not SYN-ACK packets
    if "S" not in tcp_flags or "A" in tcp_flags:
        return "NONE"

    key = (src, dst)
    packet_history = scan_tracker[key]

    # Add current destination port
    packet_history.append((current_time, dst_port))

    # Remove entries older than 10 seconds
    while packet_history and current_time - packet_history[0][0] > WINDOW_SECONDS:
        packet_history.popleft()

    # Count unique destination ports
    unique_ports = {port for _, port in packet_history}

    # Detect a possible port scan
    if len(unique_ports) >= PORT_THRESHOLD:
        last_alert = last_scan_alert.get(key, 0)

        if current_time - last_alert >= ALERT_COOLDOWN:
            last_scan_alert[key] = current_time

            print(
                "🚨 RULE ALERT: POSSIBLE SYN PORT SCAN",
                src, "->", dst,
                "Unique ports:", len(unique_ports)
            )

        return "PORT_SCAN"

    return "NONE"


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

    # Build the same 12 features used during model training
    features = pd.DataFrame([{
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_size": size,
        "protocol": protocol_map.get(protocol, 0),
        "tcp_syn": int("S" in tcp_flags),
        "tcp_ack": int("A" in tcp_flags),
        "tcp_fin": int("F" in tcp_flags),
        "tcp_rst": int("R" in tcp_flags),
        "tcp_psh": int("P" in tcp_flags),
        "tcp_urg": int("U" in tcp_flags),
        "tcp_ece": int("E" in tcp_flags),
        "tcp_cwr": int("C" in tcp_flags)
    }])

    # Layer 1: AI anomaly detection
    prediction = model.predict(features)[0]

    if prediction == -1:
        ai_result = "ANOMALOUS"
    else:
        ai_result = "NORMAL"

    # Layer 2: Rule-based port scan detection
    rule_result = "NONE"

    if protocol == "TCP":
        rule_result = check_port_scan(
            src, dst, dst_port, tcp_flags
        )

    # Combine both detection layers
    if ai_result == "ANOMALOUS" or rule_result == "PORT_SCAN":
        detection_result = "ANOMALOUS"
    else:
        detection_result = "NORMAL"

    timestamp = datetime.now().isoformat()

    # Print detection information
    if rule_result == "PORT_SCAN":
        print(
            "🚨 PORT SCAN DETECTED:",
            src, "->", dst,
            "Port:", dst_port,
            "AI:", ai_result
        )

    elif ai_result == "ANOMALOUS":
        print(
            "🚨 AI ALERT:",
            src, "->", dst,
            protocol,
            "Ports:", src_port, "->", dst_port,
            "Flags:", tcp_flags
        )

    else:
        print(
            "NORMAL TRAFFIC:",
            src, "->", dst,
            protocol
        )

    # Save both detection results
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
            tcp_flags,
            ai_result,
            rule_result,
            detection_result
        ])


print("AI-powered Network Intrusion Detection System started!")
print("Monitoring interface: enp0s8")
print("AI Detection: Enabled")
print("Rule-Based SYN Port Scan Detection: Enabled")
print("Scan threshold:", PORT_THRESHOLD, "unique ports in", WINDOW_SECONDS, "seconds")
print("Press CTRL+C to stop monitoring.")

sniff(
    iface="enp0s8",
    prn=detect_packet,
    store=False
)

