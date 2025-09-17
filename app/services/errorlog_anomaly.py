import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import json
import numpy as np

class ErrorLogProcessor:
    def __init__(self):
        # Modèle de détection d'anomalies
        self.scaler = MinMaxScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
        # Suivi des erreurs
        self.error_counts = defaultdict(int)
        self.ip_error_mapping = defaultdict(lambda: defaultdict(int))
        
        # Regex pour parsing
        self.nginx_error_regex = re.compile(
            r'^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
            r'\[(?P<severity>\w+)\] '
            r'(?P<pid>\d+)#(?P<tid>\d+): '
            r'\*(?P<cid>\d+) '
            r'(?P<message>.*)'
        )
        
        self.apache_error_regex = re.compile(
            r'^\[(?P<timestamp>\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \d{4})\] '
            r'\[(?P<module>\w+):(?P<severity>\w+)\] '
            r'(?:\[pid (?P<pid>\d+):tid (?P<tid>\d+)\] )?'
            r'(?:\[client (?P<client>\S+)\] )?'
            r'(?P<message>.*)'
        )

    def parse_log(self, line):
        """Parse un log d'erreur en JSON structuré"""
        parsed = None
        
        # Essayer Nginx puis Apache
        for pattern in [self.nginx_error_regex, self.apache_error_regex]:
            match = pattern.match(line)
            if match:
                parsed = match.groupdict()
                break
                
        if not parsed:
            return None

        # Normalisation des champs
        log_entry = {
            "timestamp": self._convert_timestamp(parsed.get('timestamp', '')),
            "severity": parsed.get('severity', '').lower(),
            "module": parsed.get('module', ''),
            "pid": int(parsed.get('pid', 0)) if parsed.get('pid') else None,
            "client_ip": parsed.get('client', '').split(':')[0] if parsed.get('client') else None,
            "message": parsed.get('message', ''),
            "raw": line.strip()
        }
        
        # Classification des erreurs
        log_entry["error_type"] = self._classify_error(log_entry["message"])
        log_entry["is_critical"] = log_entry["severity"] in ('emerg', 'alert', 'crit', 'error')
        
        return log_entry

    def _convert_timestamp(self, timestamp_str):
        """Convertit les différents formats de timestamp en ISO 8601"""
        formats = [
            "%Y/%m/%d %H:%M:%S",  # Nginx
            "%a %b %d %H:%M:%S %Y"  # Apache
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.isoformat() + "Z"
            except ValueError:
                continue
        return None

    def _classify_error(self, message):
        """Classifie le type d'erreur"""
        message = message.lower()
        
        if "connection refused" in message:
            return "connection_refused"
        elif "permission denied" in message:
            return "permission_denied"
        elif "file not found" in message:
            return "file_not_found"
        elif "timeout" in message:
            return "timeout"
        elif "ssl" in message:
            return "ssl_error"
        else:
            return "other"

    def extract_features(self, log):
        """Extrait les features pour analyse ML"""
        return {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "severity_level": self._severity_to_numeric(log["severity"]),
            "is_critical": 1 if log["is_critical"] else 0,
            "error_type": self._error_type_to_numeric(log["error_type"]),
            "message_length": len(log["message"])
        }

    def _severity_to_numeric(self, severity):
        """Convertit la sévérité en valeur numérique"""
        levels = {
            'emerg': 5,
            'alert': 4,
            'crit': 3,
            'error': 2,
            'warn': 1,
            'notice': 0,
            'info': 0,
            'debug': 0
        }
        return levels.get(severity, 0)

    def _error_type_to_numeric(self, error_type):
        """Convertit le type d'erreur en valeur numérique"""
        types = {
            'connection_refused': 4,
            'permission_denied': 3,
            'ssl_error': 3,
            'file_not_found': 2,
            'timeout': 2,
            'other': 1
        }
        return types.get(error_type, 0)

    def detect_issues(self, logs):
        """Détecte les problèmes via règles et ML"""
        alerts = []
        
        for log in logs:
            # 1. Détection attaques par force brute
            if log["client_ip"] and "invalid user" in log["message"].lower():
                self.ip_error_mapping[log["client_ip"]]["auth_failures"] += 1
                if self.ip_error_mapping[log["client_ip"]]["auth_failures"] > 10:
                    alerts.append({
                        "type": "brute_force",
                        "ip": log["client_ip"],
                        "count": self.ip_error_mapping[log["client_ip"]]["auth_failures"],
                        "message": log["message"][:100] + "..."
                    })
            
            # 2. Détection erreurs répétées
            error_key = f"{log['module']}_{log['error_type']}"
            self.error_counts[error_key] += 1
            if self.error_counts[error_key] > 50:  # Seuil
                alerts.append({
                    "type": "repeated_errors",
                    "error": error_key,
                    "count": self.error_counts[error_key],
                    "severity": log["severity"]
                })
            
            # 3. Détection erreurs critiques
            if log["is_critical"]:
                alerts.append({
                    "type": "critical_error",
                    "module": log["module"],
                    "message": log["message"][:100] + "..."
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
    processor = ErrorLogProcessor()
    
    # Exemple de logs d'erreur
    logs = [
        "2023/07/01 10:15:23 [error] 1234#5678: *9012 connect() failed (111: Connection refused) while connecting to upstream",
        "[Sat Jul 01 10:15:24 2023] [auth:error] [pid 8765] [client 192.168.1.10:54321] Invalid user 'admin'",
        "2023/07/01 10:15:25 [crit] 1234#5678: *9013 SSL handshake failed",
        "[Sat Jul 01 10:15:26 2023] [core:error] [pid 8765] [client 192.168.1.10:54321] File does not exist: /var/www/admin.php"
    ]
    
    # Traitement
    parsed_logs = [processor.parse_log(log) for log in logs if processor.parse_log(log)]
    analyzed_logs, alerts = processor.detect_issues(parsed_logs)
    
    # Résultats
    print("=== Logs d'erreur analysés ===")
    for log in analyzed_logs:
        print(json.dumps(log, indent=2, default=to_serializable))

    
    print("\n=== Alertes ===")
    for alert in alerts:
        print(f"[{alert['type'].upper()}] {alert.get('ip', alert.get('error', ''))} - {alert.get('count', '')}")
