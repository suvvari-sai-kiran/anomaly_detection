import os
import time
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ICMP
import mysql.connector
import mysql_logger

USE_LOCAL_BLOCKING = bool(int(os.environ.get("USE_LOCAL_BLOCKING", "0")))
REM_DEVICE_HOST = os.environ.get("DEVICE_HOST", "172.16.2.6")

def train_anomaly_model(df):
    features = ['src_port','dest_port','packets','bytes_sent']
    X = df[features]
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    joblib.dump(model, 'isolation_forest_model.pkl')
    print("Model trained -> isolation_forest_model.pkl")
    return model

def block_ip_local(ip):
    try:
        subprocess.check_call(["netsh", "advfirewall", "firewall", "add", "rule",
                               "name=Block_"+ip, "dir=in", "action=block", "remoteip="+ip])
        return True, "Windows firewall block added"
    except Exception as e:
        return False, str(e)

def block_ip_on_device(ip):
    print(f"Simulating block on device {REM_DEVICE_HOST} for {ip}")
    return True, f"simulated device {REM_DEVICE_HOST}"

def capture_packets(interface=None, packet_count=10):
    packets = sniff(count=packet_count, iface=interface)
    records = []
    for pkt in packets:
        if IP in pkt:
            proto = "OTHER"
            sport = 0
            dport = 0
            if TCP in pkt:
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"
            records.append({
                'src_ip': pkt[IP].src,
                'dest_ip': pkt[IP].dst,
                'src_port': sport,
                'dest_port': dport,
                'protocol': proto,
                'packets': 1,
                'bytes_sent': len(pkt)
            })
    return pd.DataFrame(records)

def safe_insert_flow(record):
    """Try inserting into MySQL with retries."""
    for attempt in range(3):
        try:
            mysql_logger.insert_flow(record)
            return True
        except mysql.connector.Error as err:
            print(f"[WARN] MySQL insert failed (attempt {attempt+1}): {err}")
            time.sleep(2)
    print("[ERROR] Failed to insert flow after 3 attempts")
    return False

def safe_insert_blocked(ip, device=None, reason=None):
    for attempt in range(3):
        try:
            mysql_logger.insert_blocked_ip(ip, device=device, reason=reason)
            return True
        except mysql.connector.Error as err:
            print(f"[WARN] MySQL insert_blocked failed (attempt {attempt+1}): {err}")
            time.sleep(2)
    print("[ERROR] Failed to insert blocked IP after 3 attempts")
    return False

def main():
    mysql_logger.init_db()

    try:
        model = joblib.load('isolation_forest_model.pkl')
        print("Loaded existing anomaly model.")
    except FileNotFoundError:
        print("Training new model with sample data...")
        import random
        from faker import Faker
        fake = Faker()
        data = []
        for _ in range(10000):
            data.append([
                fake.ipv4(),
                fake.ipv4(),
                random.randint(1024,65535),
                random.randint(1,65535),
                random.choice(['TCP','UDP','ICMP']),
                random.randint(1,1000),
                random.randint(64,1500)
            ])
        df = pd.DataFrame(data, columns=['src_ip','dest_ip','src_port','dest_port','protocol','packets','bytes_sent'])
        model = train_anomaly_model(df)

    interface = os.environ.get("CAPTURE_INTERFACE")  # e.g., "Wi-Fi", "Ethernet", "eth0"
    print(f"[INFO] Capturing from interface: {interface or 'default'}")

    try:
        while True:
            live_df = capture_packets(interface=interface, packet_count=10)
            if live_df.empty:
                continue

            for _, row in live_df.iterrows():
                # FIX: Pass DataFrame with feature names to avoid sklearn warning
                features_df = pd.DataFrame([[
                    row['src_port'],
                    row['dest_port'],
                    row['packets'],
                    row['bytes_sent']
                ]], columns=['src_port', 'dest_port', 'packets', 'bytes_sent'])

                is_anom = 1 if model.predict(features_df)[0] == -1 else 0
                record = {
                    "ts": datetime.now(),
                    "src_ip": row['src_ip'],
                    "dest_ip": row['dest_ip'],
                    "src_port": row['src_port'],
                    "dest_port": row['dest_port'],
                    "protocol": row['protocol'],
                    "packets": row['packets'],
                    "bytes_sent": row['bytes_sent'],
                    "is_anomaly": is_anom,
                    "action_taken": "none"
                }

                if is_anom:
                    print(f"\n[ALERT] Anomaly detected: {row['src_ip']}")
                    if USE_LOCAL_BLOCKING:
                        ok, msg = block_ip_local(row['src_ip'])
                    else:
                        ok, msg = block_ip_on_device(row['src_ip'])
                    record["action_taken"] = f"{'success' if ok else 'fail'}: {msg}"
                    safe_insert_blocked(row['src_ip'], device=REM_DEVICE_HOST, reason=msg)

                safe_insert_flow(record)

            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")

if __name__ == "__main__":
    main()
