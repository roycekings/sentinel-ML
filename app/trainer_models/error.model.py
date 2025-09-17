import re
from datetime import datetime
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
import joblib

class ErrorLogProcessor:
    def __init__(self):
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
        parsed = None
        for pattern in [self.nginx_error_regex, self.apache_error_regex]:
            match = pattern.match(line)
            if match:
                parsed = match.groupdict()
                break
        if not parsed:
            return None
        log_entry = {
            "timestamp": self._convert_timestamp(parsed.get('timestamp', '')),
            "severity": parsed.get('severity', '').lower(),
            "module": parsed.get('module', ''),
            "pid": int(parsed.get('pid', 0)) if parsed.get('pid') else None,
            "client_ip": parsed.get('client', '').split(':')[0] if parsed.get('client') else None,
            "message": parsed.get('message', ''),
        }
        log_entry["error_type"] = self._classify_error(log_entry["message"])
        log_entry["is_critical"] = log_entry["severity"] in ('emerg', 'alert', 'crit', 'error')
        return log_entry

    def _convert_timestamp(self, timestamp_str):
        formats = [
            "%Y/%m/%d %H:%M:%S",
            "%a %b %d %H:%M:%S %Y"
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                return dt.isoformat() + "Z"
            except ValueError:
                continue
        return None

    def _classify_error(self, message):
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
        return {
            "hour": datetime.fromisoformat(log["timestamp"][:-1]).hour if log["timestamp"] else 0,
            "severity_level": self._severity_to_numeric(log["severity"]),
            "is_critical": 1 if log["is_critical"] else 0,
            "error_type": self._error_type_to_numeric(log["error_type"]),
            "message_length": len(log["message"])
        }

    def _severity_to_numeric(self, severity):
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
        types = {
            'connection_refused': 4,
            'permission_denied': 3,
            'ssl_error': 3,
            'file_not_found': 2,
            'timeout': 2,
            'other': 1
        }
        return types.get(error_type, 0)


if __name__ == "__main__":
    processor = ErrorLogProcessor()

    # Charge les logs d'erreur depuis un fichier texte (1 log par ligne)
    with open("error_logs.txt", "r") as f:
        raw_logs = f.readlines()

    parsed_logs = [processor.parse_log(line) for line in raw_logs if processor.parse_log(line)]
    df = pd.DataFrame([processor.extract_features(log) for log in parsed_logs])

    scaler = MinMaxScaler()
    X = scaler.fit_transform(df)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    joblib.dump((scaler, model), "models/errorlog_model.joblib")
    print("Modèle et scaler sauvegardés dans models/errorlog_model.joblib")
