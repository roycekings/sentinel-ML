import re
from datetime import datetime
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
import joblib
import os

class KernLogProcessor:
    def __init__(self):
        # Regex adaptée à : 2025-07-30T01:32:51.612899+00:00 test kernel: ...
        self.kern_regex = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+\d{2}:\d{2}))\s'
            r'(?P<host>\S+)\s+kernel:\s(?P<message>.*)$'
        )
        self.oom_pattern = re.compile(r'Out of memory: Kill process (?P<pid>\d+) \((?P<process>\S+)\)')

    def parse_log(self, line):
        match = self.kern_regex.match(line)
        if not match:
            return None
        parsed = match.groupdict()
        ts = self._convert_timestamp(parsed['timestamp'])

        log_entry = {
            "timestamp": ts,
            "host": parsed['host'],
            "message": parsed['message'],
            "event_type": self._classify_event(parsed['message']),
        }

        if log_entry["event_type"] == "oom_kill":
            oom_match = self.oom_pattern.search(parsed['message'])
            if oom_match:
                log_entry.update({
                    "oom_pid": int(oom_match.group('pid')),
                    "oom_process": oom_match.group('process')
                })

        return log_entry

    def _convert_timestamp(self, ts_str):
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).isoformat()
        except:
            return None

    def _classify_event(self, message):
        message = message.lower()
        if "out of memory" in message:
            return "oom_kill"
        elif "usb disconnect" in message:
            return "usb_disconnect"
        elif "error" in message:
            return "hardware_error"
        elif "warning" in message:
            return "hardware_warning"
        elif "syn flood" in message:
            return "syn_flood"
        else:
            return "system_event"

    def extract_features(self, log):
        return {
            "hour": datetime.fromisoformat(log["timestamp"]).hour if log["timestamp"] else 0,
            "is_error": 1 if log["event_type"] in ("oom_kill", "hardware_error") else 0,
            "is_warning": 1 if log["event_type"] == "hardware_warning" else 0,
            "is_network": 1 if "br-" in log["message"] or "veth" in log["message"] else 0,
            "is_storage": 1 if any(x in log["message"] for x in ["sd", "hd", "nvme"]) else 0,
            "message_length": len(log["message"])
        }

if __name__ == "__main__":
    processor = KernLogProcessor()

    with open("kern.txt", "r", encoding="utf-8") as f:
        raw_logs = [line.strip() for line in f if line.strip()]

    parsed_logs = []
    for line in raw_logs:
        log = processor.parse_log(line)
        if log:
            parsed_logs.append(log)

    if not parsed_logs:
        print("❌ Aucun log parsé. Vérifie ton format ou ta regex.")
        exit()

    df = pd.DataFrame([processor.extract_features(log) for log in parsed_logs])

    if df.empty:
        print("❌ Aucune donnée exploitable pour entraînement.")
        exit()

    scaler = MinMaxScaler()
    X = scaler.fit_transform(df)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    os.makedirs("models", exist_ok=True)
    joblib.dump((scaler, model), "models/kernlog_model.joblib")
    print("✅ Modèle et scaler sauvegardés dans models/kernlog_model.joblib")
