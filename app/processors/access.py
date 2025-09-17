import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
import json
import numpy as np
import joblib

class AccessLogProcessor:
    def __init__(self, model_path="models/accesslog_model.joblib"):
        # Charger le scaler et le modèle déjà entraîné
        self.scaler, self.model = joblib.load(model_path)

        # États internes
        self.ip_request_counts = defaultdict(int)
        self.ip_error_counts = defaultdict(int)
        self.user_agents = defaultdict(int)

        # Regex Apache & Nginx
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
        parsed = None
        for pattern in [self.apache_regex, self.nginx_regex]:
            match = pattern.match(line)
            if match:
                parsed = match.groupdict()
                break
        if not parsed:
            return None

        return {
            "timestamp": self._convert_timestamp(parsed.get('timestamp', '')),
            "remote_ip": parsed.get('ip') or parsed.get('remote_addr'),
            "method": parsed.get('method'),
            "path": parsed.get('path') or parsed.get('uri'),
            "status": int(parsed.get('status', 0)),
            "size": int(parsed.get('size') or parsed.get('body_bytes_sent', 0)),
            "referrer": parsed.get('referrer') or parsed.get('http_referer'),
            "user_agent": parsed.get('user_agent') or parsed.get('http_user_agent'),
            "raw": line,
            "is_static": self._is_static_resource(parsed.get('path') or parsed.get('uri')),
            "is_admin": "/admin" in (parsed.get('path') or parsed.get('uri'))
        }

    def _convert_timestamp(self, timestamp_str):
        try:
            dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except:
            return None

    def _is_static_resource(self, path):
        return path.endswith(('.js', '.css', '.jpg', '.png', '.ico'))

    def extract_features(self, log):
        return {
            "hour": datetime.fromisoformat(log["timestamp"]).hour if log["timestamp"] else 0,
            "status": log["status"],
            "size": min(log["size"], 10_000_000),
            "is_error": 1 if log["status"] >= 400 else 0,
            "is_static": 1 if log["is_static"] else 0,
            "is_admin": 1 if log["is_admin"] else 0
        }

    def detect_attacks(self, logs):
        alerts = []
        for log in logs:
            ip = log["remote_ip"]

            self.ip_request_counts[ip] += 1
            if self.ip_request_counts[ip] > 1000:
                alerts.append({"type": "ddos", "ip": ip, "count": self.ip_request_counts[ip], "log": log})

            if log["status"] in (401, 403):
                self.ip_error_counts[ip] += 1
                if self.ip_error_counts[ip] > 20:
                    alerts.append({"type": "brute_force", "ip": ip, "count": self.ip_error_counts[ip], "log": log})

            ua = log["user_agent"].lower()
            if "sqlmap" in ua or "nikto" in ua or "zap" in ua:
                alerts.append({"type": "scanner", "ip": ip, "tool": ua, "log": log})

        if logs:
            df = pd.DataFrame([self.extract_features(log) for log in logs])
            X = self.scaler.transform(df)
            scores = self.model.decision_function(X)

            for i, log in enumerate(logs):
                log["anomaly_score"] = float(scores[i])
                log["is_anomaly"] = scores[i] < -0.3

        return logs, alerts
