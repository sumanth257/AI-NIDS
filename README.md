# AI-Powered Network Intrusion Detection System (AI-NIDS)

## Project Overview
AI-NIDS is a machine-learning-based Network Intrusion Detection System designed to monitor network traffic, detect suspicious activities, and generate security alerts in real time.

The project combines Machine Learning and rule-based detection techniques with a Streamlit dashboard for network security monitoring and visualization.

## Architecture

Kali Linux (Traffic Generator)
        ↓
Ubuntu Server (Packet Capture using Scapy)
        ↓
Feature Extraction
        ↓
┌─────────────────────┐
│ Isolation Forest AI │
│ Rule-Based Engine   │
└─────────────────────┘
        ↓
Anomaly Detection
        ↓
alerts.csv
        ↓
Streamlit SOC Dashboard

## Technologies Used
- Python
- Scapy
- Pandas & NumPy
- Scikit-learn
- Isolation Forest
- Streamlit
- Plotly
- Ubuntu Server
- Kali Linux
- Oracle VirtualBox

## Features
- Real-time network packet capture
- TCP, UDP, and ICMP traffic monitoring
- Machine learning anomaly detection
- Rule-based TCP SYN port scan detection
- Combined AI and rule-based alerts
- Security alert logging to CSV
- Interactive SOC dashboard
- Traffic analytics and visualization
- Security alert filtering and CSV export

## Lab Environment
- Host OS: Windows 11
- Virtualization: Oracle VirtualBox
- Sensor: Ubuntu Server
- Traffic Generator: Kali Linux
- Network: Isolated Host-Only Network

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/AI-NIDS.git
cd AI-NIDS
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Capture Network Traffic

```bash
sudo ./venv/bin/python packet_analyzer.py
```

### 2. Train the Machine Learning Model

```bash
source venv/bin/activate
python train_model.py
```

### 3. Start the Intrusion Detection System

```bash
sudo ./venv/bin/python detect_anomalies.py
```

### 4. Launch the Dashboard

Open another terminal:

```bash
cd ~/AI-NIDS
source venv/bin/activate
streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501
```

Access the dashboard:

```text
http://192.168.56.105:8501
```

## Testing

From Kali Linux, generate test traffic:

```bash
ping -c 10 192.168.56.105
```

Perform a controlled SYN scan against your lab server:

```bash
nmap -sS -p 1-100 192.168.56.105
```

Observe the detection results in the Ubuntu terminal and Streamlit dashboard.

## Disclaimer
This project is developed for educational and cybersecurity laboratory purposes. All testing should be performed only on systems and networks you own or have explicit authorization to test.
