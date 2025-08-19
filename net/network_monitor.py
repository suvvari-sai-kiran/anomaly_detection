import pandas as pd
import numpy as np
from faker import Faker
import random
import joblib
import time
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from netmiko import ConnectHandler
import getpass
import sys
from sklearn.ensemble import IsolationForest

# --- CONFIGURATION ---
# IMPORTANT: Update this section with your specific network and email details.
CONFIG = {
    # Email credentials (set as environment variables for security)
    "sender_email": os.environ.get("GMAIL_USER", "suvvarisaikiran347@gmail.com"),
    "sender_password": os.environ.get("GMAIL_PASS", "wubb jluu rscw xtnj"),
    "receiver_email": os.environ.get("GMAIL_USER", "saikiransuvvari6@gmail.com"),
    
    # Network Device Details
    "remediation_device": {
        'device_type': 'cisco_ios',  # Change this based on your switch vendor (e.g., juniper_junos, arista_eos)
        'host': '172.16.2.6',      # Replace with your switch's management IP
        'username': 'admin',       # Replace with your switch's username
        'password': 'Cent22@$#!', # Replace with your switch's password
        'secret': 'enable_password', # Replace with your enable password if required
    }
}

# --- DATA GENERATION AND MODEL TRAINING ---

def generate_network_data(num_records, anomaly_rate=0.01):
    """Generates a DataFrame of simulated network flow data."""
    print("Generating simulated training data...")
    fake = Faker()
    data = []
    
    for _ in range(num_records):
        src_ip = fake.ipv4()
        dest_ip = fake.ipv4()
        src_port = random.randint(1024, 65535)
        dest_port = random.randint(1, 65535)
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
        packets = random.randint(1, 1000)
        bytes_sent = packets * random.randint(64, 1500)
        
        data.append([src_ip, dest_ip, src_port, dest_port, protocol, packets, bytes_sent])

    df = pd.DataFrame(data, columns=['src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'packets', 'bytes_sent'])
    
    num_anomalies = int(num_records * anomaly_rate)
    anomaly_indices = np.random.choice(df.index, num_anomalies, replace=False)
    
    for idx in anomaly_indices:
        df.loc[idx, 'dest_port'] = random.randint(1, 100)
        df.loc[idx, 'packets'] = random.randint(1000, 5000)
        df.loc[idx, 'bytes_sent'] = df.loc[idx, 'packets'] * random.randint(1, 50)
    
    df['is_anomaly'] = False
    df.loc[anomaly_indices, 'is_anomaly'] = True
    
    return df

def train_anomaly_model(df):
    """Trains an Isolation Forest model and saves it."""
    print("Training Isolation Forest model...")
    features = ['src_port', 'dest_port', 'packets', 'bytes_sent']
    X = df[features]
    
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    
    joblib.dump(model, 'isolation_forest_model.pkl')
    print("Model trained and saved as 'isolation_forest_model.pkl'.")
    return model

# --- REAL-TIME DETECTION AND RESPONSE ---

def send_anomaly_email(anomalous_ip):
    """Sends an email alert for a detected anomaly."""
    sender_email = CONFIG["sender_email"]
    sender_password = CONFIG["sender_password"]
    receiver_email = CONFIG["receiver_email"]

    if "your_app_password" in sender_password or "your_email" in sender_email:
        print("Email credentials not configured. Skipping email alert.")
        return

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "CRITICAL ANOMALY DETECTED!"
    
    body = f"""
    An anomaly has been detected in the network.
    
    Source IP: {anomalous_ip}
    Remediation action: IP has been automatically blocked.
    
    Please log in to the network device to verify this action.
    """
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        print("Email alert sent successfully!")
    except Exception as e:
        print(f"Failed to send email. Error: {e}")
    finally:
        server.quit()

def block_ip_on_device(ip_to_block, device_info):
    """Simulates connecting to a network device and blocking an IP."""
    print(f"--- Triggering REMEDIATION for IP: {ip_to_block} ---")
    try:
        print(f"Attempting to connect to {device_info['host']}...")
        
        # NOTE: This part is a simulation. You must replace this with your switch's actual commands.
        # Example for a Cisco IOS device is shown below.
        # with ConnectHandler(**device_info) as net_connect:
        #     net_connect.enable()
        #     config_commands = [
        #         f'ip access-list extended BLOCK_ANOMALY_IPS',
        #         f'deny ip host {ip_to_block} any',
        #         f'permit ip any any'
        #     ]
        #     net_connect.send_config_set(config_commands)
        #     net_connect.send_command('write memory')
        
        print(f"Simulating command: 'ip access-list extended BLOCK_ANOMALY_IPS; deny ip host {ip_to_block} any'")
        print("Action complete.")
        
    except Exception as e:
        print(f"Error: Could not connect or apply configuration. {e}")

def get_realtime_network_data():
    """Simulates getting one new network flow record."""
    data = {
        'src_ip': '192.168.1.' + str(random.randint(10, 200)),
        'src_port': random.randint(1024, 65535),
        'dest_port': random.randint(1, 65535),
        'packets': random.randint(100, 5000),
        'bytes_sent': random.randint(1000, 100000)
    }

    if random.randint(1, 50) == 1:
        data['src_ip'] = '10.0.0.' + str(random.randint(10, 99))
        data['dest_port'] = random.randint(1, 100)
        data['packets'] = random.randint(5000, 10000)
        data['bytes_sent'] = data['packets'] * random.randint(1, 50)
    
    return pd.DataFrame([data])

def main():
    # --- TRAINING PHASE ---
    try:
        model = joblib.load('isolation_forest_model.pkl')
        print("Anomaly detection model loaded successfully.")
    except FileNotFoundError:
        print("Model file not found. Generating data and training a new model...")
        simulated_data = generate_network_data(10000)
        model = train_anomaly_model(simulated_data)

    # --- REAL-TIME DETECTION PHASE ---
    print("\nStarting real-time network anomaly detection. Press Ctrl+C to stop.")
    try:
        while True:
            live_df = get_realtime_network_data()
            features = ['src_port', 'dest_port', 'packets', 'bytes_sent']
            
            if not all(feature in live_df.columns for feature in features):
                print("Warning: Missing features in live data. Skipping detection.")
                time.sleep(2)
                continue

            is_anomaly = model.predict(live_df[features])[0]
            
            if is_anomaly == -1:
                malicious_ip = live_df['src_ip'].iloc[0]
                print(f"\nANOMALY DETECTED! Source IP: {malicious_ip}")
                send_anomaly_email(malicious_ip)
                block_ip_on_device(malicious_ip, CONFIG["remediation_device"])
            else:
                print(".", end="", flush=True)
                
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\nDetection process stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()