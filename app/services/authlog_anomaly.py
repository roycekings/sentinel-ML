import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import json
import numpy as np

class AuthLogProcessor:
    def __init__(self):
        # Modèle de détection d'anomalies
        self.scaler = MinMaxScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
        # Suivi des états pour détection d'attaques
        self.failed_attempts = defaultdict(int)
        self.ip_user_mapping = defaultdict(lambda: defaultdict(int))
        self.successful_logins = defaultdict(int)
        
        # Regex pour parsing
        self.auth_regex = re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s'
            r'(?P<host>\S+)\s'
            r'(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s'
            r'(?P<message>.*)$'
        )
        
        self.ssh_regex = re.compile(
            r'(?:Failed|Accepted)\spassword\sfor\s'
            r'(?:invalid\suser\s)?(?P<user>\S+)\s'
            r'from\s(?P<ip>\S+)\sport\s(?P<port>\d+)'
        )

    def parse_log(self, line):
        """Parse un log d'authentification en JSON structuré"""
        auth_match = self.auth_regex.match(line)
        if not auth_match:
            return None

        parsed = auth_match.groupdict()
        log_entry = {
            "timestamp": self._convert_timestamp(parsed['timestamp']),
            "host": parsed['host'],
            "process": parsed['process'],
            "pid": int(parsed['pid']) if parsed.get('pid') else None,
            "message": parsed['message'],
            "raw": line.strip(),
            "event_type": self._classify_event(parsed['message'])
        }
        
        # Extraction spécifique SSH
        if log_entry["process"] == "sshd":
            ssh_match = self.ssh_regex.search(parsed['message'])
            if ssh_match:
                log_entry.update({
                    "user": ssh_match.group('user'),
                    "source_ip": ssh_match.group('ip'),
                    "port": int(ssh_match.group('port')),
                    "auth_success": "Accepted" in parsed['message']
                })
        
        return log_entry

    def _convert_timestamp(self, timestamp_str):
        """Convertit le timestamp en ISO 8601"""
        try:
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.now().year)
            return dt.isoformat() + "Z"
        except:
            return None

    def _classify_event(self, message):
        """Classifie le type d'événement"""
        message = message.lower()
        if "failed password" in message:
            return "auth_failure"
        elif "accepted password" in message:
            return "auth_success"
        elif "invalid user" in message:
            return "invalid_user"
        elif "session opened" in message:
            return "session_open"
        elif "session closed" in message:
            return "session_close"
        else:
            return "other"

    def extract_features(self, log):
        """Extrait les features pour analyse ML"""
        features = {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "is_auth_failure": 1 if log["event_type"] == "auth_failure" else 0,
            "is_invalid_user": 1 if log["event_type"] == "invalid_user" else 0,
            "is_root": 1 if log.get("user") == "root" else 0,
            "same_ip_diff_users": 0,
            "failures_last_hour": 0
        }
        
        # Features contextuelles
        if log.get("source_ip"):
            features["same_ip_diff_users"] = len(self.ip_user_mapping[log["source_ip"]])
            features["failures_last_hour"] = self.failed_attempts[log["source_ip"]]
            
        return features

    def detect_attacks(self, logs):
        """Détecte les attaques via règles et ML"""
        alerts = []
        
        for log in logs:
            # Mise à jour des compteurs
            if log.get("source_ip"):
                if log["event_type"] == "auth_failure":
                    self.failed_attempts[log["source_ip"]] += 1
                    self.ip_user_mapping[log["source_ip"]][log.get("user", "unknown")] += 1
                elif log["event_type"] == "auth_success":
                    self.successful_logins[log["source_ip"]] += 1
            
            # 1. Détection brute force SSH
            if log["event_type"] in ("auth_failure", "invalid_user"):
                ip = log.get("source_ip")
                if ip and self.failed_attempts[ip] > 5:  # Seuil
                    alerts.append({
                        "type": "brute_force",
                        "ip": ip,
                        "count": self.failed_attempts[ip],
                        "target_user": log.get("user"),
                        "timestamp": log["timestamp"]
                    })
            
            # 2. Détection attaque par dictionnaire
            if (log.get("source_ip") and 
                len(self.ip_user_mapping[log["source_ip"]]) > 3):
                alerts.append({
                    "type": "dictionary_attack",
                    "ip": log["source_ip"],
                    "users_tried": len(self.ip_user_mapping[log["source_ip"]]),
                    "timestamp": log["timestamp"]
                })
            
            # 3. Détection accès root inhabituel
            if (log.get("user") == "root" and 
                log["event_type"] == "auth_success" and
                self.successful_logins.get(log["source_ip"], 0) == 1):
                alerts.append({
                    "type": "root_access",
                    "ip": log["source_ip"],
                    "timestamp": log["timestamp"]
                })
        
        # Analyse ML des anomalies
        if logs:
            df = pd.DataFrame([self.extract_features(log) for log in logs])
            X = self.scaler.fit_transform(df)
            self.model.fit(X) 
            scores = self.model.decision_function(X)
            
            for i, log in enumerate(logs):
                log["anomaly_score"] = float(scores[i])
                log["is_anomaly"] = scores[i] < -0.2  # Seuil
        
        return logs, alerts
    
def to_serializable(val):
        if isinstance(val, (np.bool_, np.int64, np.float64)):
            return val.item()
        return val

# Exemple d'utilisation
if __name__ == "__main__":
    processor = AuthLogProcessor()
    
    # Exemple de logs d'authentification
    logs = [
        "Jun 26 10:15:23 server1 sshd[1234]: Failed password for root from 192.168.1.10 port 54321 ssh2",
        "Jun 26 10:15:24 server1 sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 54321 ssh2",
        "Jun 26 10:15:25 server1 sshd[1234]: Accepted password for user1 from 192.168.1.20 port 54322 ssh2",
        "Jun 26 10:15:26 server1 sshd[1234]: Failed password for root from 192.168.1.10 port 54321 ssh2",
        "Jun 26 10:15:27 server1 sshd[1234]: Accepted password for root from 192.168.1.30 port 54323 ssh2"
    ]
    
    # Traitement
    parsed_logs = [processor.parse_log(log) for log in logs if processor.parse_log(log)]
    analyzed_logs, alerts = processor.detect_attacks(parsed_logs)
    
    # Résultats
    print("=== Logs d'authentification analysés ===")
    for log in analyzed_logs:
        print(json.dumps(log, indent=2, default=to_serializable))

    
    print("\n=== Alertes ===")
    for alert in alerts:
        print(f"[{alert['type'].upper()}] {alert['ip']} - {alert.get('count', '')}")
