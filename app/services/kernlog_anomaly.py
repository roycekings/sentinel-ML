import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import json
import numpy as np

class KernLogProcessor:
    def __init__(self):
        # Modèle de détection d'anomalies
        self.scaler = MinMaxScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
        # Suivi des états pour détection d'attaques
        self.memory_errors = defaultdict(int)
        self.disk_errors = defaultdict(int)
        self.oom_events = []
        
        # Regex pour parsing
        self.kern_regex = re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s'
            r'(?P<host>\S+)\s'
            r'kernel:\s(?:\[(?P<kernel_timestamp>\d+\.\d+)\]\s)?'
            r'(?P<component>\w+)(?:\((?P<device>\S+)\))?:\s'
            r'(?P<message>.*)$'
        )
        
        # Patterns de détection
        self.oom_pattern = re.compile(r'Out of memory: Kill process (?P<pid>\d+) \((?P<process>\S+)\)')
        self.usb_pattern = re.compile(r'USB disconnect, device number \d+')

    def parse_log(self, line):
        """Parse un log kernel en JSON structuré"""
        match = self.kern_regex.match(line)
        if not match:
            return None

        parsed = match.groupdict()
        log_entry = {
            "timestamp": self._convert_timestamp(parsed['timestamp']),
            "host": parsed['host'],
            "kernel_timestamp": float(parsed['kernel_timestamp']) if parsed.get('kernel_timestamp') else None,
            "component": parsed['component'],
            "device": parsed.get('device'),
            "message": parsed['message'],
            "raw": line.strip(),
            "event_type": self._classify_event(parsed['message'])
        }
        
        # Extraction spécifique OOM Killer
        if log_entry["event_type"] == "oom_kill":
            oom_match = self.oom_pattern.search(parsed['message'])
            if oom_match:
                log_entry.update({
                    "oom_pid": int(oom_match.group('pid')),
                    "oom_process": oom_match.group('process')
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
        """Classifie le type d'événement kernel"""
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
        """Extrait les features pour analyse ML"""
        return {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "is_error": 1 if log["event_type"] in ("oom_kill", "hardware_error") else 0,
            "is_warning": 1 if log["event_type"] == "hardware_warning" else 0,
            "is_network": 1 if "network" in log["component"].lower() else 0,
            "is_storage": 1 if log["device"] and any(x in log["device"] for x in ["sd", "hd", "nvme"]) else 0,
            "message_length": len(log["message"])
        }

    def detect_issues(self, logs):
        """Détecte les problèmes matériels et de sécurité"""
        alerts = []
        
        for log in logs:
            # Mise à jour des compteurs
            if log["event_type"] == "oom_kill":
                self.oom_events.append(log)
            elif log["event_type"] == "hardware_error":
                if log.get("device"):
                    self.disk_errors[log["device"]] += 1
            
            # 1. Détection attaques SYN flood
            if log["event_type"] == "syn_flood":
                alerts.append({
                    "type": "syn_flood",
                    "source": log["message"].split("from ")[-1].split(" ")[0],
                    "timestamp": log["timestamp"],
                    "raw": log["raw"]
                })
            
            # 2. Détection problèmes matériels
            if log["event_type"] == "hardware_error" and log.get("device"):
                if self.disk_errors[log["device"]] > 3:
                    alerts.append({
                        "type": "disk_failure",
                        "device": log["device"],
                        "count": self.disk_errors[log["device"]],
                        "timestamp": log["timestamp"]
                    })
            
            # 3. Détection OOM Killer fréquent
            if log["event_type"] == "oom_kill":
                if len(self.oom_events) > 2:
                    alerts.append({
                        "type": "memory_leak",
                        "count": len(self.oom_events),
                        "last_process": log.get("oom_process"),
                        "timestamp": log["timestamp"]
                    })
            
            # 4. Détection périphériques USB suspects
            if log["event_type"] == "usb_disconnect":
                if "storage" in log["message"].lower():
                    alerts.append({
                        "type": "usb_storage_removed",
                        "device": log.get("device", "unknown"),
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
                log["is_anomaly"] = scores[i] < -0.25  # Seuil
        
        return logs, alerts


def to_serializable(val):
        if isinstance(val, (np.bool_, np.int64, np.float64)):
            return val.item()
        return val
# Exemple d'utilisation
if __name__ == "__main__":
    processor = KernLogProcessor()
    
    # Exemple de logs kernel
    logs = [
        "Jun 26 15:10:23 server1 kernel: [12345.678901] Out of memory: Kill process 1234 (python) score 789",
        "Jun 26 15:10:24 server1 kernel: [12345.678902] EXT4-fs error (device sda1): ext4_find_entry: reading directory #12345678",
        "Jun 26 15:10:25 server1 kernel: [12345.678903] TCP: SYN flood from 192.168.1.100 port 54321",
        "Jun 26 15:10:26 server1 kernel: [12345.678904] usb 2-1.2: USB disconnect, device number 4",
        "Jun 26 15:10:27 server1 kernel: [12345.678905] EXT4-fs (sda1): warning: mounting fs with errors"
    ]
    
    # Traitement
    parsed_logs = [processor.parse_log(log) for log in logs if processor.parse_log(log)]
    analyzed_logs, alerts = processor.detect_issues(parsed_logs)
    
    # Résultats
    print("=== Logs kernel analysés ===")
    for log in analyzed_logs:
        print(json.dumps(log, indent=2, default=to_serializable))

    
    print("\n=== Alertes ===")
    for alert in alerts:
        print(f"[{alert['type'].upper()}] {alert.get('device', alert.get('source', ''))}")
