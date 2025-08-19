import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from dotenv import load_dotenv
load_dotenv()

MODEL_PATH = "isolation_forest_model.pkl"
CONTAM = float(os.getenv("IFOREST_CONTAM", "0.01"))

FEATURES = ['src_port', 'dest_port', 'packets', 'bytes_sent']

def train_model_from_dataframe(df: pd.DataFrame):
    X = df[FEATURES].copy()
    model = IsolationForest(contamination=CONTAM, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    return model

def load_or_train(min_bootstrap_rows=5000):
    try:
        return joblib.load(MODEL_PATH)
    except FileNotFoundError:
        # bootstrap: synthesize benign-ish traffic if no model yet
        import numpy as np
        import random
        data = []
        for _ in range(min_bootstrap_rows):
            data.append([
                random.randint(1024, 65535),          # src_port
                random.randint(1, 65535),             # dest_port
                random.randint(1, 800),               # packets
                random.randint(64, 1200)*random.randint(1, 800) # bytes
            ])
        df = pd.DataFrame(data, columns=FEATURES)
        return train_model_from_dataframe(df)
