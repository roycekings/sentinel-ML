import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import re
from datetime import datetime

# Ce parseur simple sert juste à l'entraînement depuis un fichier de logs
LOG_REGEX = re.compile(
    r'^(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) (?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status>\d{3}) (?P<size>\d+) ".*" ".*"$'
)

def parse_log_line(line):
    match = LOG_REGEX.match(line)
    if not match:
        return None
    data = match.groupdict()
    return {
        "timestamp": datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S %z").isoformat(),
        "path": data["path"],
        "status": int(data["status"]),
        "size": int(data["size"]),
        "is_static": data["path"].endswith(('.js', '.css', '.jpg', '.png', '.ico')),
        "is_admin": "/admin" in data["path"]
    }

def extract_features(log):
    return {
        "hour": datetime.fromisoformat(log["timestamp"]).hour,
        "status": log["status"],
        "size": min(log["size"], 10_000_000),
        "is_error": 1 if log["status"] >= 400 else 0,
        "is_static": 1 if log["is_static"] else 0,
        "is_admin": 1 if log["is_admin"] else 0
    }

def train_and_save_model(log_file_path, output_model_path):
    logs = []
    with open(log_file_path, 'r') as f:
        for line in f:
            log = parse_log_line(line)
            if log:
                logs.append(extract_features(log))

    df = pd.DataFrame(logs)
    scaler = MinMaxScaler()
    X = scaler.fit_transform(df)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    # Sauvegarder le modèle et le scaler
    joblib.dump((scaler, model), output_model_path)
    print(f"✅ Modèle sauvegardé dans : {output_model_path}")

if __name__ == "__main__":
    train_and_save_model("access.log", "models/accesslog_model.joblib")
