import re
from datetime import datetime
import pandas as pd
from collections import defaultdict
from sklearn.preprocessing import MinMaxScaler
import joblib
import json
import os
import numpy as np
from app.services.log_service import Anomalie_service

class AuthLogProcessor:
    def __init__(self, model_path="app/models/authLog_model.joblib", scaler_path="app/models/authLog_scaler.joblib"):
        self.failed_attempts = defaultdict(int)
        self.ip_user_mapping = defaultdict(lambda: defaultdict(int))
        self.successful_logins = defaultdict(int)

        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            raise FileNotFoundError(
                f"🚨 Modèle ou scaler manquant :\n- {model_path if not os.path.exists(model_path) else ''}\n- {scaler_path if not os.path.exists(scaler_path) else ''}\n💡 Lance le script d'entraînement avant de démarrer l'app."
            )

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        
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
        match = self.auth_regex.match(line)
        if not match:
            return None

        g = match.groupdict()
        try:
            timestamp = datetime.strptime(g['timestamp'], "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=datetime.now().year)
            ts_iso = timestamp.isoformat() + "Z"
        except:
            ts_iso = None
        
        base_log = {
            "timestamp": ts_iso,
            "host": g['host'],
            "process": g['process'],
            "pid": int(g['pid']) if g['pid'] else None,
            "message": g['message'],
            "raw": line
        }
        
        if base_log["process"] == "sshd":
            ssh_match = self.ssh_regex.search(base_log["message"])
            if ssh_match:
                ssh = ssh_match.groupdict()
                base_log.update({
                    "user": ssh.get('user'),
                    "source_ip": ssh.get('ip'),
                    "port": int(ssh.get('port')),
                    "auth_success": "Accepted" in base_log["message"]
                })
        
        return base_log

    def extract_features(self, log):
        features = {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "is_auth_failure": 1 if "Failed password" in log.get("message", "") else 0,
            "is_invalid_user": 1 if "invalid user" in log.get("message", "").lower() else 0,
            "is_root": 1 if log.get("user") == "root" else 0,
            "same_ip_diff_users": 0,
            "failures_last_hour": 0
        }
        
        if log.get("source_ip"):
            features["same_ip_diff_users"] = len(self.ip_user_mapping[log["source_ip"]])
            features["failures_last_hour"] = self.failed_attempts[log["source_ip"]]
        
        return features

    async def detect_attacks(self, logs, device_name):
        alerts = []
        
        for log in logs:
            ip = log.get("source_ip")
            user = log.get("user")
            event_type = None
            msg = log.get("message", "").lower()
            
            if ip:
                if "failed password" in msg:
                    self.failed_attempts[ip] += 1
                    self.ip_user_mapping[ip][user or "unknown"] += 1
                    event_type = "auth_failure"
                elif "accepted password" in msg:
                    self.successful_logins[ip] += 1
                    event_type = "auth_success"
                elif "invalid user" in msg:
                    event_type = "invalid_user"
            
            # 1. Brute force SSH
            if ip and self.failed_attempts[ip] > 5:
                alerts.append({
                    "type": "brute_force",
                    "ip": ip,
                    "count": self.failed_attempts[ip],
                    "target_user": user,
                    "timestamp": log.get("timestamp")
                })
            
            # 2. Attaque par dictionnaire (plusieurs utilisateurs testés)
            if ip and len(self.ip_user_mapping[ip]) > 3:
                alerts.append({
                    "type": "dictionary_attack",
                    "ip": ip,
                    "users_tried": len(self.ip_user_mapping[ip]),
                    "timestamp": log.get("timestamp")
                })
            
            # 3. Accès root inhabituel (premier succès root)
            if ip and user == "root" and "accepted password" in msg:
                if self.successful_logins[ip] == 1:
                    alerts.append({
                        "type": "root_access",
                        "ip": ip,
                        "timestamp": log.get("timestamp")
                    })

        # Analyse ML anomalies
        if logs:
            df = pd.DataFrame([self.extract_features(log) for log in logs])
            if not df.empty:
                X = self.scaler.transform(df)
                scores = self.model.decision_function(X)
                for i, log in enumerate(logs):
                    log["anomaly_score"] = float(scores[i])
                    log["is_anomaly"] = scores[i] < -0.2
                    await Anomalie_service.create_anomalie(log)
        
        return logs, alerts


