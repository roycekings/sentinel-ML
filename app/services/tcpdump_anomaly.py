import re
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import json
from datetime import datetime

class NetworkLogProcessor:
    def __init__(self):
        # Modèle pour détection d'anomalies
        self.scaler = MinMaxScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
        # Suivi des états pour détection d'attaques
        self.ip_connection_counts = defaultdict(int)
        self.port_scan_counts = defaultdict(int)
        self.syn_flood_counts = defaultdict(int)
        
        # Expression régulière pour parsing tcpdump
        self.tcpdump_regex = re.compile(
            r'^(?P<timestamp>\d{2}:\d{2}:\d{2}\.\d+)\s'
            r'(?P<protocol>\w+)\s'
            r'(?P<src_ip>\S+?)\.(?P<src_port>\d+)\s'
            r'>\s'
            r'(?P<dst_ip>\S+?)\.(?P<dst_port>\d+):\s'
            r'(?P<flags>\w+)?.*?\s'
            r'(?P<size>\d+)\sbytes?'
        )

    def parse_log(self, line):
        """Parse un log tcpdump en JSON structuré"""
        match = self.tcpdump_regex.match(line)
        if not match:
            print('je comprend')
            return None

        parsed = match.groupdict()
        
        
        log_entry = {
            "timestamp": self._convert_timestamp(parsed['timestamp']),
            "protocol": parsed['protocol'],
            "src_ip": parsed['src_ip'],
            "src_port": int(parsed['src_port']),
            "dst_ip": parsed['dst_ip'],
            "dst_port": int(parsed['dst_port']),
            "flags": parsed.get('flags', ''),
            "size": int(parsed['size']),
            "raw": line.strip()
        }
        
        # Détection basique de type de trafic
        log_entry["is_syn"] = 'S' in log_entry["flags"] and 'A' not in log_entry["flags"]
        log_entry["is_dns"] = log_entry["dst_port"] == 53
        log_entry["is_http"] = log_entry["dst_port"] in (80, 443)
        
        return log_entry

    def _convert_timestamp(self, ts):
        """Convertit le timestamp tcpdump en ISO 8601"""
        try:
            dt = datetime.strptime(ts, "%H:%M:%S.%f")
            return dt.replace(year=datetime.now().year).isoformat() + "Z"
        except:
            return None

    def extract_features(self, log):
        """Extrait les features pour analyse ML"""
        return {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "src_port": log["src_port"],
            "dst_port": log["dst_port"],
            "size": min(log["size"], 1500),  # MTU standard
            "is_syn": 1 if log["is_syn"] else 0,
            "is_dns": 1 if log["is_dns"] else 0,
            "is_http": 1 if log["is_http"] else 0
        }

    def detect_attacks(self, logs):
        """Détecte les attaques via règles et ML"""
        alerts = []
        
        for log in logs:
            src_ip = log["src_ip"]
            
            # 1. Détection scan de ports
            if log["is_syn"]:
                self.port_scan_counts[src_ip] += 1
                if self.port_scan_counts[src_ip] > 50:  # Seuil
                    alerts.append({
                        "type": "port_scan",
                        "ip": src_ip,
                        "count": self.port_scan_counts[src_ip],
                        "target": log["dst_ip"]
                    })
            
            # 2. Détection SYN flood
            if log["is_syn"] and log["dst_port"] in (80, 443):
                self.syn_flood_counts[src_ip] += 1
                if self.syn_flood_counts[src_ip] > 1000:  # Seuil
                    alerts.append({
                        "type": "syn_flood",
                        "ip": src_ip,
                        "count": self.syn_flood_counts[src_ip],
                        "target_port": log["dst_port"]
                    })
            
            # 3. Détection exfiltration (gros transferts)
            if log["size"] > 1000000:  # 1MB
                alerts.append({
                    "type": "data_exfiltration",
                    "ip": src_ip,
                    "size": log["size"],
                    "destination": f"{log['dst_ip']}:{log['dst_port']}"
                })
        
        # Analyse ML des anomalies
        if logs:
            df = pd.DataFrame([self.extract_features(log) for log in logs])
            X = self.scaler.fit_transform(df)
            scores = self.model.decision_function(X)
            
            for i, log in enumerate(logs):
                log["anomaly_score"] = float(scores[i])
                log["is_anomaly"] = scores[i] < -0.25  # Seuil
        
        return logs, alerts
    

# Exemple d'utilisation
if __name__ == "__main__":
    processor = NetworkLogProcessor()
    
    # Exemple de logs tcpdump
    logs = [
        "10:15:23.456789 IP 192.168.1.10.54321 > 10.0.0.1.80: Flags [S], seq 12345, length 0",
        "10:15:23.567890 IP 192.168.1.10.54322 > 10.0.0.1.443: Flags [S], seq 12346, length 0",
        "10:15:24.123456 IP 192.168.1.5.53 > 8.8.8.8.53: 512+ A? example.com (45)",
        "10:15:25.789012 IP 192.168.1.20.12345 > 10.0.0.2.22: Flags [P.], seq 1:1001, ack 1, length 1000"
    ]
    
    # Traitement
    parsed_logs = [processor.parse_log(log) for log in logs if processor.parse_log(log)]
    analyzed_logs, alerts = processor.detect_attacks(parsed_logs)
    
    # Résultats
    print("=== Logs réseau analysés ===")
    for log in analyzed_logs:
        print(json.dumps(log, indent=2))
    
    print("\n=== Alertes ===")
    for alert in alerts:
        print(f"[{alert['type'].upper()}] {alert['ip']} - {alert.get('count', '')} {alert.get('target', '')}")
