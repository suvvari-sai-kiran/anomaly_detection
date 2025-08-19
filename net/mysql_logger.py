import mysql.connector
from datetime import datetime
from contextlib import closing
from mysql_config import get_db_config

def _conn():
    return mysql.connector.connect(**get_db_config())

def init_db():
    """Ensure database connection works and required tables exist."""
    CREATE_TABLE_FLOWS = """
    CREATE TABLE IF NOT EXISTS network_flows (
      id INT AUTO_INCREMENT PRIMARY KEY,
      ts DATETIME NOT NULL,
      src_ip VARCHAR(45),
      dest_ip VARCHAR(45),
      src_port INT,
      dest_port INT,
      protocol VARCHAR(16),
      packets BIGINT,
      bytes_sent BIGINT,
      is_anomaly TINYINT(1) DEFAULT 0,
      action_taken VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;
    """
    CREATE_TABLE_BLOCKED = """
    CREATE TABLE IF NOT EXISTS blocked_ips (
      id INT AUTO_INCREMENT PRIMARY KEY,
      ip VARCHAR(45) UNIQUE,
      blocked_at DATETIME,
      device VARCHAR(100),
      reason VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB;
    """
    with closing(_conn()) as conn, conn.cursor() as cur:
        cur.execute(CREATE_TABLE_FLOWS)
        cur.fetchall()  # Ensure no unread results
        cur.execute(CREATE_TABLE_BLOCKED)
        cur.fetchall()
        conn.commit()
    print("[INFO] Tables are ready.")
    return True

def insert_flow(record: dict):
    with closing(_conn()) as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO network_flows
                (ts, src_ip, dest_ip, src_port, dest_port, protocol, packets, bytes_sent, is_anomaly, action_taken)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            record.get("ts", datetime.now()),
            record.get("src_ip"),
            record.get("dest_ip"),
            record.get("src_port"),
            record.get("dest_port"),
            record.get("protocol"),
            record.get("packets"),
            record.get("bytes_sent"),
            int(record.get("is_anomaly", 0)),
            record.get("action_taken")
        ))
        conn.commit()

def fetch_latest(limit=100):
    with closing(_conn()) as conn, conn.cursor(dictionary=True) as cur:
        cur.execute("""
            SELECT id, ts, src_ip, dest_ip, src_port, dest_port, protocol, packets, bytes_sent, is_anomaly, action_taken
            FROM network_flows ORDER BY ts DESC LIMIT %s
        """, (limit,))
        return cur.fetchall()

def insert_blocked_ip(ip, device=None, reason=None, at=None):
    at = at or datetime.now()
    with closing(_conn()) as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO blocked_ips (ip, blocked_at, device, reason)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE blocked_at=VALUES(blocked_at), device=VALUES(device), reason=VALUES(reason)
        """, (ip, at, device, reason))
        conn.commit()

def fetch_blocked(limit=100):
    with closing(_conn()) as conn, conn.cursor(dictionary=True) as cur:
        cur.execute("SELECT id, ip, blocked_at, device, reason FROM blocked_ips ORDER BY blocked_at DESC LIMIT %s", (limit,))
        return cur.fetchall()

def unblock_ip(ip):
    with closing(_conn()) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM blocked_ips WHERE ip=%s", (ip,))
        conn.commit()
