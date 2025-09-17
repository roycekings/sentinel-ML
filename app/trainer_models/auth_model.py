import re
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import joblib

class AuthLogTrainer:
    def __init__(self):
        self.scaler = MinMaxScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        # Regex adaptée au timestamp ISO 8601 suivi des autres champs
        self.auth_regex = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+\d{2}:\d{2}|Z))\s'
            r'(?P<host>\S+)\s'
            r'(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s'
            r'(?P<message>.*)$'
        )
        self.ssh_regex = re.compile(
            r'(?:Failed|Accepted)\spassword\sfor\s'
            r'(?:invalid\suser\s)?(?P<user>\S+)\s'
            r'from\s(?P<ip>\S+)\sport\s(?P<port>\d+)'
        )

    def _convert_timestamp(self, ts):
        try:
            # Convertit le timestamp ISO en datetime, gère le "Z" et le fuseau horaire
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.isoformat()
        except Exception:
            return None

    def parse_log(self, line):
        match = self.auth_regex.match(line)
        if not match:
            return None

        parsed = match.groupdict()
        log_entry = {
            "timestamp": self._convert_timestamp(parsed['timestamp']),
            "host": parsed['host'],
            "process": parsed['process'],
            "pid": int(parsed['pid']) if parsed.get('pid') else None,
            "message": parsed['message']
        }

        if parsed['process'] == "sshd":
            ssh_match = self.ssh_regex.search(parsed['message'])
            if ssh_match:
                log_entry.update({
                    "user": ssh_match.group('user'),
                    "source_ip": ssh_match.group('ip'),
                    "port": int(ssh_match.group('port')),
                    "auth_success": "Accepted" in parsed['message']
                })

        return log_entry

    def extract_features(self, log):
        return {
            "hour": datetime.fromisoformat(log["timestamp"]).hour if log["timestamp"] else 0,
            "is_auth_failure": 1 if "Failed password" in log["message"] else 0,
            "is_invalid_user": 1 if "invalid user" in log["message"].lower() else 0,
            "is_root": 1 if log.get("user") == "root" else 0,
            "message_length": len(log["message"])
        }

    def train(self, filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            raw_logs = [line.strip() for line in f if line.strip()]

        parsed = []
        for line in raw_logs:
            try:
                log = self.parse_log(line)
                if log:
                    parsed.append(log)
            except Exception as e:
                print(f"[WARN] Erreur parsing ligne : {line[:50]}... {e}")

        features = [self.extract_features(log) for log in parsed]
        df = pd.DataFrame(features)

        if df.empty:
            print("Aucune donnée exploitable. Arrêt de l'entraînement.")
            return

        print(df.head())  # Debug

        X = self.scaler.fit_transform(df)
        self.model.fit(X)
        joblib.dump(self.model, "authlog_model.joblib")
        joblib.dump(self.scaler, "authlog_scaler.joblib")
        print(f"[✓] Modèle et scaler entraînés et sauvegardés à partir de {filepath}.")

if __name__ == "__main__":
    trainer = AuthLogTrainer()
    trainer.train("auth.txt")
