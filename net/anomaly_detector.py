import mysql.connector
from scapy.all import sniff, IP
from mysql_config import get_db_config
import time

# Threshold for anomaly detection
PACKET_THRESHOLD = 50
time_window = 10
packet_count = {}

def insert_traffic(src_ip, dst_ip, protocol, length):
    conn = mysql.connector.connect(**get_db_config())
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO traffic2025_logs (src_ip, dst_ip, protocol, length) VALUES (%s, %s, %s, %s)",
        (src_ip, dst_ip, protocol, length)
    )
    conn.commit()
    cursor.close()
    conn.close()

def insert_anomaly(ip):
    conn = mysql.connector.connect(**get_db_config())
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO anomaly2025_ips (src_ip) VALUES (%s)",
        (ip,)
    )
    conn.commit()
    cursor.close()
    conn.close()

def detect(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)

        insert_traffic(src, dst, proto, length)

        now = time.time()
        packet_count.setdefault(src, []).append(now)
        packet_count[src] = [t for t in packet_count[src] if now - t <= time_window]

        if len(packet_count[src]) > PACKET_THRESHOLD:
            print(f"ANOMALY DETECTED! {src}")
            insert_anomaly(src)

if __name__ == "__main__":
    print("Starting anomaly detector...")
    sniff(prn=detect, store=False)
