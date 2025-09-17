
import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import json
import numpy as np

class LogProcessor:
    def __init__(self):
        self.ssh_attempts = defaultdict(int)
        self.ip_activity = defaultdict(int)
        self.scaler = MinMaxScaler()
        self.model = IsolationForest(contamination=0.1, random_state=42)

        self.syslog_pattern = re.compile(
            r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
            r"(?P<host>\S+)\s(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$")

        self.ssh_failed_pattern = re.compile(
            r"Failed password for (?P<user>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)")

    def parse_log(self, line):
        match = self.syslog_pattern.match(line)
        if not match:
            return None

        variables = match.groupdict()

        base_log = {
            "timestamp": self._convert_timestamp(variables.get('timestamp', '')),
            "host": variables.get('host', ''),
            "process": variables.get('process', ''),
            "pid": int(variables.get('pid', 0)) if variables.get('pid') else None,
            "message": variables.get('message', ''),
            "raw": line,
            "severity": self._detect_severity(variables.get('message', ''))
        }

        # Extraction SSH
        if base_log["process"] == "sshd" and "Failed password" in base_log["message"]:
            ssh_match = self.ssh_failed_pattern.search(base_log["message"])
            if ssh_match:
                ssh_vars = ssh_match.groupdict()
                base_log.update({
                    "auth_user": ssh_vars.get('user'),
                    "source_ip": ssh_vars.get('source_ip'),
                    "port": int(ssh_vars.get('port', 0))
                })

        return base_log

    def _convert_timestamp(self, timestamp_str):
        try:
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            dt = dt.replace(year=datetime.now().year)
            return dt.isoformat() + "Z"
        except:
            return None

    def _detect_severity(self, message):
        message = message.lower()
        if "error" in message: return 3
        elif "warn" in message or "fail" in message: return 2
        return 1

    def extract_features(self, log):
        return {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "severity": log.get("severity", 1),
            "msg_length": len(log.get("message", "")),
            "is_ssh": 1 if log.get("process") == "sshd" else 0,
            "is_cron": 1 if log.get("process") == "CRON" else 0,
            "is_auth_failure": 1 if "Failed password" in log.get("message", "") else 0
        }

    def detect_attacks(self, logs):
        alerts = []
        for log in logs:
            if log.get("process") == "sshd" and "Failed password" in log.get("message", ""):
                ip = log.get("source_ip")
                if ip:
                    self.ssh_attempts[ip] += 1
                    if self.ssh_attempts[ip] > 5:
                        alerts.append({"type": "brute_force", "ip": ip, "count": self.ssh_attempts[ip], "log": log})

            if log.get("process") == "kernel" and "SYN" in log.get("message", ""):
                self.ip_activity[log.get("host")] += 1
                if self.ip_activity[log.get("host")] > 50:
                    alerts.append({"type": "port_scan", "host": log.get("host"), "count": self.ip_activity[log.get("host")], "log": log})

        df = pd.DataFrame([self.extract_features(log) for log in logs])
        if not df.empty:
            X = self.scaler.fit_transform(df)
            self.model.fit(X)
            scores = self.model.decision_function(X)
            for i, log in enumerate(logs):
                log["anomaly_score"] = float(scores[i])
                log["is_anomaly"] = scores[i] < -0.2

        return logs, alerts
def to_serializable(val):
        if isinstance(val, (np.bool_, np.int64, np.float64)):
            return val.item()
        return val

if __name__ == "__main__":
    processor = LogProcessor()

    logs = [
        "Jun 26 15:10:01 server1 CRON[1234]: (root) CMD (run-parts /etc/cron.daily)",
        "Jun 26 15:10:02 server1 sshd[5678]: Failed password for root from 192.168.1.10 port 22 ssh2",
        "Jun 26 15:10:03 server1 sshd[5678]: Failed password for root from 192.168.1.10 port 22 ssh2",
        "Jun 26 15:10:04 server1 kernel: [123456] TCP: SYN flood on port 80 from 10.0.0.5",
        "Jun 26 15:10:05 server1 sshd[5678]: Accepted password for user1 from 192.168.1.20 port 22 ssh2"
    ]

    parsed_logs = [processor.parse_log(log) for log in logs if processor.parse_log(log)]
    analyzed_logs, alerts = processor.detect_attacks(parsed_logs)

    print("=== Logs analysés ===")
    for log in analyzed_logs:
        print(json.dumps(log, indent=2, default=to_serializable))

    print("\n=== Alertes ===")
    for alert in alerts:
        print(f"[{alert['type'].upper()}] {alert.get('ip', alert.get('host'))} - {alert['count']} occurrences")
