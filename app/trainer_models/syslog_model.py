import re
from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import joblib
import os

# LOG_PATTERN = re.compile(
#     r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
#     r"(?P<host>\S+)\s(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
# )

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
)


def parse_log(line):
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    g = match.groupdict()
    try:
        timestamp = datetime.fromisoformat(g['timestamp'].replace("Z", "+00:00"))
        ts_iso = timestamp.isoformat()
    except:
        ts_iso = None

    return {
        "timestamp": ts_iso,
        "host": g['host'],
        "process": g['process'],
        "pid": int(g['pid']) if g['pid'] else None,
        "message": g['message'],
        "severity": detect_severity(g['message']),
    }

def detect_severity(message: str) -> int:
    msg = message.lower()
    if "error" in msg: return 3
    if "warn" in msg or "fail" in msg: return 2
    return 1

def extract_features(log):
    return {
        # "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
        "hour": datetime.fromisoformat(log["timestamp"]).hour if log["timestamp"] else 0,
        "severity": log.get("severity", 1),
        "msg_length": len(log.get("message", "")),
        "is_ssh": 1 if log.get("process") == "sshd" else 0,
        "is_cron": 1 if log.get("process") == "CRON" else 0,
        "is_auth_failure": 1 if "Failed password" in log.get("message", "") else 0
    }

def train_syslog_model(log_file: str, model_path: str):
    logs = []
    with open(log_file, 'r') as f:
        for line in f:
            log = parse_log(line)
            if log:
                logs.append(extract_features(log))

    df = pd.DataFrame(logs)
    if df.empty:
        print("Aucune donnée exploitable.")
        return

    scaler = MinMaxScaler()
    X = scaler.fit_transform(df)

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump((scaler, model), model_path)
    print(f"✅ Modèle syslog sauvegardé dans {model_path}")

if __name__ == "__main__":
    train_syslog_model("syslog.txt", "models/syslog_model.joblib")
