import os
import time
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
import paramiko
import mysql_logger
from datetime import datetime

load_dotenv()

POLL_SECONDS = int(os.getenv("POLL_SECONDS", 10))
VLAN_ID = os.getenv("VLAN_ID", "1")

# ---------- SWITCH CONNECTION ----------
def connect_to_switch():
    vendor = os.getenv("SWITCH_VENDOR", "cisco_xe")
    host = os.getenv("SWITCH_HOST")
    user = os.getenv("SWITCH_USERNAME")
    password = os.getenv("SWITCH_PASSWORD")
    enable_pw = os.getenv("SWITCH_ENABLE_PASSWORD")

    device = {
        "device_type": vendor,  # First try SSH
        "host": host,
        "username": user,
        "password": password,
        "secret": enable_pw if enable_pw else None,
    }

    try:
        print(f"[INFO] Trying SSH to {host} ({vendor})...")
        conn = ConnectHandler(**device)
        if enable_pw:
            conn.enable()
        print("[INFO] SSH connection successful.")
        return conn

    except (NetmikoAuthenticationException, NetmikoTimeoutException, paramiko.ssh_exception.SSHException) as e:
        print(f"[WARN] SSH failed: {e}")
        print("[INFO] Trying Telnet...")

        try:
            device["device_type"] = vendor + "_telnet"
            conn = ConnectHandler(**device)
            if enable_pw:
                conn.enable()
            print("[INFO] Telnet connection successful.")
            return conn
        except Exception as e2:
            print(f"[ERROR] Telnet also failed: {e2}")
            return None

# ---------- ACL FUNCTIONS ----------
def ensure_acl_exists_and_applied(conn, vlan_id):
    acl_name = "NETMON_BLOCK"
    print(f"[INFO] Ensuring ACL '{acl_name}' exists on VLAN {vlan_id}...")
    conn.send_config_set([
        f"ip access-list extended {acl_name}",
        "remark Blocked by Network Monitor"
    ])
    conn.send_config_set([
        f"interface vlan {vlan_id}",
        f"ip access-group {acl_name} in"
    ])
    print("[INFO] ACL applied.")

def add_ip_to_acl(conn, ip):
    acl_name = "NETMON_BLOCK"
    cmd = f"ip access-list extended {acl_name}"
    conn.send_config_set([
        cmd,
        f"deny ip host {ip} any"
    ])
    print(f"[ACTION] IP {ip} blocked via ACL.")
    return f"Blocked {ip} via ACL"

def remove_ip_from_acl(conn, ip):
    acl_name = "NETMON_BLOCK"
    conn.send_config_set([
        f"ip access-list extended {acl_name}",
        f"no deny ip host {ip} any"
    ])
    print(f"[ACTION] IP {ip} unblocked from ACL.")
    return f"Unblocked {ip} from ACL"

# ---------- BLOCK / UNBLOCK ----------
def block_ip(ip):
    conn = connect_to_switch()
    if not conn:
        return False, "Switch connection failed"
    try:
        ensure_acl_exists_and_applied(conn, VLAN_ID)
        msg = add_ip_to_acl(conn, ip)
        mysql_logger.insert_blocked_ip(ip, device=os.getenv("SWITCH_HOST"), reason=msg)
        return True, msg
    except Exception as e:
        return False, str(e)
    finally:
        conn.disconnect()

def unblock_ip(ip):
    conn = connect_to_switch()
    if not conn:
        return False, "Switch connection failed"
    try:
        msg = remove_ip_from_acl(conn, ip)
        return True, msg
    except Exception as e:
        return False, str(e)
    finally:
        conn.disconnect()

# ---------- MONITOR LOOP ----------
def fetch_connected_hosts(conn):
    output = conn.send_command("show ip arp", use_textfsm=True)
    return output if isinstance(output, list) else []

def main():
    mysql_logger.init_db()
    host = os.getenv("SWITCH_HOST")
    print(f"[INFO] Monitoring switch {host} every {POLL_SECONDS} seconds...")

    while True:
        conn = connect_to_switch()
        if conn:
            try:
                hosts = fetch_connected_hosts(conn)
                ts = datetime.now()
                for h in hosts:
                    record = {
                        "ts": ts,
                        "src_ip": h.get("address"),
                        "dest_ip": None,
                        "src_port": None,
                        "dest_port": None,
                        "protocol": None,
                        "packets": None,
                        "bytes_sent": None,
                        "is_anomaly": 0,
                        "action_taken": None
                    }
                    if record["src_ip"]:
                        mysql_logger.insert_flow(record)
                print(f"[INFO] Recorded {len(hosts)} hosts.")
            except Exception as e:
                print(f"[ERROR] Failed to fetch hosts: {e}")
            finally:
                conn.disconnect()
        else:
            print("[ERROR] Could not connect to switch.")
        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
