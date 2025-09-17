import re
from collections import defaultdict
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
from datetime import datetime
import joblib

class TcpdumpProcessor:
    def __init__(self, model_path="models/tcpdump_model.joblib"):
        self.ip_conn = defaultdict(int)
        self.syn_flood = defaultdict(int)
        self.port_scans = defaultdict(int)
        self.scaler, self.model = joblib.load(model_path)

        self.regex = re.compile(
            r'^(?P<timestamp>\d{2}:\d{2}:\d{2}\.\d+)\s'
            r'(?P<protocol>\w+)\s'
            r'(?P<src_ip>\S+?)\.(?P<src_port>\d+)\s>\s'
            r'(?P<dst_ip>\S+?)\.(?P<dst_port>\d+):.*?Flags\s\[(?P<flags>[^\]]+)\].*?length\s(?P<size>\d+)'
        )

    def parse_log(self, line):
        match = self.regex.match(line)
        if not match:
            return None
        g = match.groupdict()

        return {
            "timestamp": self._convert_ts(g["timestamp"]),
            "protocol": g["protocol"],
            "src_ip": g["src_ip"],
            "src_port": int(g["src_port"]),
            "dst_ip": g["dst_ip"],
            "dst_port": int(g["dst_port"]),
            "flags": g.get("flags", ""),
            "size": int(g["size"]),
            "is_syn": "S" in g["flags"] and "A" not in g["flags"],
            "is_dns": int(g["dst_port"]) == 53,
            "is_http": int(g["dst_port"]) in (80, 443),
            "raw": line.strip()
        }

    def _convert_ts(self, ts):
        try:
            dt = datetime.strptime(ts, "%H:%M:%S.%f")
            return dt.replace(year=datetime.now().year).isoformat() + "Z"
        except:
            return None

    def extract_features(self, log):
        return {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "src_port": log["src_port"],
            "dst_port": log["dst_port"],
            "size": min(log["size"], 1500),
            "is_syn": 1 if log["is_syn"] else 0,
            "is_dns": 1 if log["is_dns"] else 0,
            "is_http": 1 if log["is_http"] else 0
        }

    def detect_attacks(self, logs):
        alerts = []

        for log in logs:
            src_ip = log["src_ip"]

            if log["is_syn"]:
                self.port_scans[src_ip] += 1
                if self.port_scans[src_ip] > 50:
                    alerts.append({
                        "type": "port_scan",
                        "ip": src_ip,
                        "count": self.port_scans[src_ip],
                        "target": log["dst_ip"]
                    })

            if log["is_syn"] and log["dst_port"] in (80, 443):
                self.syn_flood[src_ip] += 1
                if self.syn_flood[src_ip] > 1000:
                    alerts.append({
                        "type": "syn_flood",
                        "ip": src_ip,
                        "count": self.syn_flood[src_ip],
                        "target_port": log["dst_port"]
                    })

            if log["size"] > 1_000_000:
                alerts.append({
                    "type": "data_exfiltration",
                    "ip": src_ip,
                    "size": log["size"],
                    "destination": f"{log['dst_ip']}:{log['dst_port']}"
                })

        df = pd.DataFrame([self.extract_features(log) for log in logs])
        if not df.empty:
            X = self.scaler.transform(df)
            scores = self.model.decision_function(X)
            for i, log in enumerate(logs):
                log["anomaly_score"] = float(scores[i])
                log["is_anomaly"] = scores[i] < -0.25

        return logs, alerts
