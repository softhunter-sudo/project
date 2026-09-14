from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import os

connection_tracker = defaultdict(set)
PORT_SCAN_THRESHOLD = 10

MY_IP = "192.168.100.96"   # your actual IP

LOG_FILE = os.path.join("logs", "traffic_log.txt")

def log_line(text):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {text}\n")

def handle_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if src_ip != MY_IP:
            connection_tracker[src_ip].add(dst_port)
            num_ports = len(connection_tracker[src_ip])

            if num_ports > PORT_SCAN_THRESHOLD:
                alert = f"⚠️ ALERT: Possible port scan from {src_ip} — {num_ports} different ports contacted!"
                print(alert)
                log_line(alert)
            else:
                line = f"{src_ip} -> port {dst_port} (unique ports so far: {num_ports})"
                print(line)
                log_line(line)

print(f"Logging to {LOG_FILE} ... capturing traffic.")
sniff(prn=handle_packet, count=100)