from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import threading
import socket

app = Flask(__name__)

MY_IP = socket.gethostbyname(socket.gethostname())
PORT_SCAN_THRESHOLD = 10

# Instead of a flat event list, track per-IP summary data
ip_summary = {}
alerts = []

def handle_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if src_ip != MY_IP:
            if src_ip not in ip_summary:
                ip_summary[src_ip] = {
                    "ports": set(),
                    "packet_count": 0,
                    "last_seen": None
                }

            ip_summary[src_ip]["ports"].add(dst_port)
            ip_summary[src_ip]["packet_count"] += 1
            ip_summary[src_ip]["last_seen"] = datetime.now().strftime("%H:%M:%S")

            num_ports = len(ip_summary[src_ip]["ports"])
            if num_ports > PORT_SCAN_THRESHOLD:
                alert_msg = f"Possible port scan from {src_ip} — {num_ports} ports"
                if alert_msg not in alerts:
                    alerts.append(alert_msg)

def start_sniffing():
    sniff(prn=handle_packet, store=False)

sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/traffic")
def get_traffic():
    # Build a clean summary list, sorted by most unique ports (most "suspicious" first)
    summary_list = []
    for ip, data in ip_summary.items():
        summary_list.append({
            "src_ip": ip,
            "unique_ports": len(data["ports"]),
            "packet_count": data["packet_count"],
            "last_seen": data["last_seen"]
        })

    summary_list.sort(key=lambda x: x["unique_ports"], reverse=True)

    return jsonify({
        "events": summary_list[:30],   # top 30 most active IPs
        "alerts": alerts[::-1]
    })

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)