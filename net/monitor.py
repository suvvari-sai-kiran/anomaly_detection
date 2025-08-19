import os, time
from datetime import datetime
import pandas as pd
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP, UDP, ICMP
from detector import load_or_train, FEATURES
import mysql_logger
import switch_blocker

load_dotenv()

IFACE = os.getenv("CAPTURE_INTERFACE") or None
BATCH = int(os.getenv("PACKETS_PER_BATCH", "25"))

# Keep a small in-memory recent decision to avoid re-blocking the same IP repeatedly
_recent_blocked = {}

def _packet_to_row(pkt):
    if IP not in pkt:
        return None
    proto, sport, dport = "OTHER", 0, 0
    if TCP in pkt:
        proto = "TCP"; sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "UDP"; sport = int(pkt[UDP].sport); dport = int(pkt[UDP].dport)
    elif ICMP in pkt:
        proto = "ICMP"
    return {
        "ts": datetime.now(),
        "src_ip": pkt[IP].src,
        "dest_ip": pkt[IP].dst,
        "protocol": proto,
        "src_port": sport,
        "dest_port": dport,
        "packets": 1,
        "bytes_sent": len(pkt),
        "is_anomaly": 0,
        "action_taken": None
    }

def main():
    print(f"[INFO] Loading anomaly model…")
    model = load_or_train()
    print("[INFO] Model ready.")

    mysql_logger.init_db()

    print(f"[INFO] Starting packet capture on: {IFACE or 'default'}  (batch={BATCH})")
    while True:
        try:
            pkts = sniff(count=BATCH, iface=IFACE)
        except Exception as e:
            print(f"[ERROR] sniff failed: {e}")
            time.sleep(2)
            continue

        rows = []
        for pkt in pkts:
            row = _packet_to_row(pkt)
            if row: rows.append(row)

        if not rows:
            continue

        df = pd.DataFrame(rows)
        # Build features DataFrame exactly in the right order
        fdf = pd.DataFrame({
            'src_port': df.get('src_port', 0),
            'dest_port': df.get('dest_port', 0),
            'packets': df.get('packets', 0),
            'bytes_sent': df.get('bytes_sent', 0),
        })

        preds = model.predict(fdf)  # 1 normal, -1 anomaly
        for i, pred in enumerate(preds):
            r = rows[i]
            if pred == -1:
                ip = r["src_ip"]
                r["is_anomaly"] = 1
                print(f"[ALERT] Anomaly: {ip} → {r['dest_ip']} proto={r['protocol']} bytes={r['bytes_sent']}")
                # Throttle re-blocks within ~60s
                tnow = time.time()
                if ip not in _recent_blocked or tnow - _recent_blocked[ip] > 60:
                    try:
                        msg = switch_blocker.block_ip(ip)
                        r["action_taken"] = f"block-ok: {msg}"
                        _recent_blocked[ip] = tnow
                    except Exception as e:
                        r["action_taken"] = f"block-fail: {e}"
                else:
                    r["action_taken"] = "recently-blocked-skip"
                # persist to blocked_ips table as well
                try:
                    mysql_logger.insert_blocked_ip(ip, device=os.getenv("SWITCH_HOST"), reason=r["action_taken"])
                except Exception as e:
                    print(f"[WARN] failed to record blocked ip: {e}")

            # Always log the flow (normal or anomaly)
            try:
                mysql_logger.insert_flow({
                    "ts": r["ts"],
                    "src_ip": r["src_ip"],
                    "dest_ip": r["dest_ip"],
                    "protocol": r["protocol"],
                    "packets": r["packets"],
                    "bytes_sent": r["bytes_sent"],
                    "is_anomaly": r["is_anomaly"],
                    "action_taken": r["action_taken"]
                })
            except Exception as e:
                print(f"[WARN] DB insert failed: {e}")
