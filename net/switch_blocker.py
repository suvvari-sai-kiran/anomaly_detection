import os
from dotenv import load_dotenv
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
import paramiko

load_dotenv()

VENDOR = os.getenv("SWITCH_VENDOR", "cisco_xe")
HOST = os.getenv("SWITCH_HOST")
USER = os.getenv("SWITCH_USERNAME")
PASS = os.getenv("SWITCH_PASSWORD")
ENABLE = os.getenv("SWITCH_ENABLE_PASSWORD") or None
ACL_VLAN_ID = os.getenv("ACL_VLAN_ID", "1")
ACL_NAME = os.getenv("ACL_NAME", "NETMON_BLOCK")

def _connect():
    dev = {
        "device_type": VENDOR,
        "host": HOST,
        "username": USER,
        "password": PASS,
        "secret": ENABLE
    }
    try:
        conn = ConnectHandler(**dev)
        if ENABLE:
            conn.enable()
        return conn
    except (NetmikoAuthenticationException, NetmikoTimeoutException, paramiko.SSHException) as e:
        # try telnet fallback
        dev["device_type"] = f"{VENDOR}_telnet"
        conn = ConnectHandler(**dev)
        if ENABLE:
            conn.enable()
        return conn

def ensure_acl(conn):
    # create ACL and apply on VLAN in direction IN
    conn.send_config_set([
        f"ip access-list extended {ACL_NAME}",
        "remark Blocked by NetMon",
    ])
    conn.send_config_set([
        f"interface vlan {ACL_VLAN_ID}",
        f"ip access-group {ACL_NAME} in"
    ])

def block_ip(ip: str) -> str:
    conn = _connect()
    try:
        ensure_acl(conn)
        conn.send_config_set([
            f"ip access-list extended {ACL_NAME}",
            f"deny ip host {ip} any",
            "permit ip any any"
        ])
        return f"Blocked {ip} via ACL {ACL_NAME} on VLAN {ACL_VLAN_ID}"
    finally:
        conn.disconnect()

def unblock_ip(ip: str) -> str:
    conn = _connect()
    try:
        conn.send_config_set([
            f"ip access-list extended {ACL_NAME}",
            f"no deny ip host {ip} any"
        ])
        return f"Unblocked {ip} from ACL {ACL_NAME}"
    finally:
        conn.disconnect()
