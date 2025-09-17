import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import json
import numpy as np

class AccessLogProcessor:
    def __init__(self):
        # Modèle pour détection d'anomalies
        self.scaler = MinMaxScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
        # Suivi des états pour détection d'attaques
        self.ip_request_counts = defaultdict(int)
        self.ip_error_counts = defaultdict(int)
        self.user_agents = defaultdict(int)
        
        # Expressions régulières pour parsing
        self.apache_regex = re.compile(
            r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>\S+) (?P<protocol>HTTP/\d\.\d)" '
            r'(?P<status>\d{3}) (?P<size>\d+) "(?P<referrer>[^"]*)" '
            r'"(?P<user_agent>[^"]*)"'
        )
        self.nginx_regex = re.compile(
            r'^(?P<remote_addr>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<uri>\S+) (?P<protocol>HTTP/\d\.\d)" '
            r'(?P<status>\d{3}) (?P<body_bytes_sent>\d+) '
            r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
        )
    

    def parse_log(self, line):
        """Parse un log d'accès Nginx/Apache en JSON structuré"""
        parsed = None
        
        # Essayer Apache puis Nginx
        for pattern in [self.apache_regex, self.nginx_regex]:
            match = pattern.match(line)
            if match:
                parsed = match.groupdict()
                break
                
        if not parsed:
            return None

        # Normalisation des champs
        log_entry = {
            "timestamp": self._convert_timestamp(parsed.get('timestamp', '')),
            "remote_ip": parsed.get('ip') or parsed.get('remote_addr'),
            "method": parsed.get('method'),
            "path": parsed.get('path') or parsed.get('uri'),
            "status": int(parsed.get('status', 0)),
            "size": int(parsed.get('size') or parsed.get('body_bytes_sent', 0)),
            "referrer": parsed.get('referrer') or parsed.get('http_referer'),
            "user_agent": parsed.get('user_agent') or parsed.get('http_user_agent'),
            "raw": line
        }
        
        # Détection basique de type de requête
        log_entry["is_static"] = self._is_static_resource(log_entry["path"])
        log_entry["is_admin"] = "/admin" in log_entry["path"]
        
        return log_entry

    def _convert_timestamp(self, timestamp_str):
        """Convertit le timestamp Apache/Nginx en ISO 8601"""
        try:
            dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except:
            return None

    def _is_static_resource(self, path):
        """Détecte si la ressource est statique"""
        static_ext = ('.js', '.css', '.jpg', '.png', '.ico')
        return path.endswith(static_ext)

    def extract_features(self, log):
        """Extrait les features pour analyse ML"""
        return {
            "hour": datetime.fromisoformat(log["timestamp"]).hour if log["timestamp"] else 0,
            "status": log["status"],
            "size": min(log["size"], 10_000_000),  # Seuil à 10MB
            "is_error": 1 if log["status"] >= 400 else 0,
            "is_static": 1 if log["is_static"] else 0,
            "is_admin": 1 if log["is_admin"] else 0
        }

    def detect_attacks(self, logs):
        """Détecte les attaques via règles et ML"""
        alerts = []
        
        for log in logs:
            ip = log["remote_ip"]
            
            # 1. Détection DDoS (trop de requêtes)
            self.ip_request_counts[ip] += 1
            if self.ip_request_counts[ip] > 1000:  # Seuil ajustable
                alerts.append({
                    "type": "ddos",
                    "ip": ip,
                    "count": self.ip_request_counts[ip],
                    "log": log
                })
            
            # 2. Détection brute force (trop d'erreurs)
            if log["status"] in (401, 403):
                self.ip_error_counts[ip] += 1
                if self.ip_error_counts[ip] > 20:  # Seuil
                    alerts.append({
                        "type": "brute_force",
                        "ip": ip,
                        "count": self.ip_error_counts[ip],
                        "log": log
                    })
            
            # 3. Détection scanners (user agents suspects)
            ua = log["user_agent"].lower()
            if "sqlmap" in ua or "nikto" in ua or "zap" in ua:
                alerts.append({
                    "type": "scanner",
                    "ip": ip,
                    "tool": ua,
                    "log": log
                })
        
        # Analyse ML des anomalies
        if logs:
            df = pd.DataFrame([self.extract_features(log) for log in logs])
            X = self.scaler.fit_transform(df)
            self.model.fit(X)
            scores = self.model.decision_function(X)
            
            for i, log in enumerate(logs):
                log["anomaly_score"] = float(scores[i])
                log["is_anomaly"] = scores[i] < -0.3  # Seuil
        
        return logs, alerts
def to_serializable(val):
        if isinstance(val, (np.bool_, np.int64, np.float64)):
            return val.item()
        return val

# Exemple d'utilisation
if __name__ == "__main__":
    processor = AccessLogProcessor()
    
    # Exemple de logs Apache/Nginx
    logs = [
        '192.168.1.10 - - [01/Jul/2023:10:12:33 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
        '10.0.0.5 - - [01/Jul/2023:10:12:34 +0000] "POST /wp-login.php HTTP/1.1" 200 1234 "-" "sqlmap/1.6"',
        '172.16.0.3 - - [01/Jul/2023:10:12:35 +0000] "GET /static/style.css HTTP/1.1" 304 0 "-" "Mozilla/5.0"',
        '192.168.1.10 - - [01/Jul/2023:10:12:36 +0000] "GET /admin/login HTTP/1.1" 401 512 "-" "Mozilla/5.0"'
    ]
    
    # Traitement
    parsed_logs = [processor.parse_log(log) for log in logs if processor.parse_log(log)]
    analyzed_logs, alerts = processor.detect_attacks(parsed_logs)
    
    # Résultats
    print("=== Logs analysés ===")
    for log in analyzed_logs:
        print(json.dumps(log, indent=2, default=to_serializable))

    
    print("\n=== Alertes ===")
    for alert in alerts:
        print(f"[{alert['type'].upper()}] {alert['ip']} - {alert.get('count', '')} {alert.get('tool', '')}")