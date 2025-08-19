import pandas as pd
import numpy as np
from faker import Faker
import random

def generate_network_data(num_records, anomaly_rate=0.01):
    """Generates a DataFrame of simulated network flow data."""
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

    # Introduce anomalies
    num_anomalies = int(num_records * anomaly_rate)
    anomaly_indices = np.random.choice(df.index, num_anomalies, replace=False)

    # Simulate a port scan anomaly
    for idx in anomaly_indices:
        df.loc[idx, 'dest_port'] = random.randint(1, 100)
        df.loc[idx, 'packets'] = random.randint(1000, 5000)
        df.loc[idx, 'bytes_sent'] = df.loc[idx, 'packets'] * random.randint(1, 50)

    df['is_anomaly'] = False
    df.loc[anomaly_indices, 'is_anomaly'] = True

    return df

if __name__ == '__main__':
    simulated_data = generate_network_data(1000)
    simulated_data.to_csv('network_data.csv', index=False)
    print("Generated 'network_data.csv' with simulated traffic.")