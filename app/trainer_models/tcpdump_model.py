import re
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import joblib
import os

TCPDUMP_REGEX = re.compile(
    r'^(?P<timestamp>\d{2}:\d{2}:\d{2}\.\d+)\s'
    r'(?P<protocol>\w+)\s'
    r'(?P<src_ip>\S+?)\.(?P<src_port>\d+)\s>\s'
    r'(?P<dst_ip>\S+?)\.(?P<dst_port>\d+):.*?Flags\s\[(?P<flags>[^\]]+)\].*?length\s(?P<size>\d+)'
)

def parse_log(line):
    match = TCPDUMP_REGEX.match(line)
    if not match:
        return None
    parsed = match.groupdict()
    timestamp = _convert_timestamp(parsed['timestamp'])

    return {
        "timestamp": timestamp,
        "protocol": parsed['protocol'],
        "src_ip": parsed['src_ip'],
        "src_port": int(parsed['src_port']),
        "dst_ip": parsed['dst_ip'],
        "dst_port": int(parsed['dst_port']),
        "flags": parsed.get('flags', ''),
        "size": int(parsed['size']),
        "is_syn": 'S' in parsed.get('flags', '') and 'A' not in parsed.get('flags', ''),
        "is_dns": int(parsed['dst_port']) == 53,
        "is_http": int(parsed['dst_port']) in (80, 443)
    }

def _convert_timestamp(ts):
    try:
        dt = datetime.strptime(ts, "%H:%M:%S.%f")
        return dt.replace(year=datetime.now().year).isoformat() + "Z"
    except:
        return None

def extract_features(log):
    return {
        "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
        "src_port": log["src_port"],
        "dst_port": log["dst_port"],
        "size": min(log["size"], 1500),
        "is_syn": 1 if log["is_syn"] else 0,
        "is_dns": 1 if log["is_dns"] else 0,
        "is_http": 1 if log["is_http"] else 0
    }

def train_model(tcpdump_path, model_path):
    logs = []
    with open(tcpdump_path, "r") as f:
        for line in f:
            log = parse_log(line)
            if log:
                logs.append(extract_features(log))

    df = pd.DataFrame(logs)
    if df.empty:
        print("⚠️ Aucun log valide trouvé.")
        return

    scaler = MinMaxScaler()
    X = scaler.fit_transform(df)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump((scaler, model), model_path)
    print(f"✅ Modèle tcpdump sauvegardé dans {model_path}")

if __name__ == "__main__":
    train_model("tcpdump.txt", "models/tcpdump_model.joblib")
