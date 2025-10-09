import re
from datetime import datetime
from collections import defaultdict
import pandas as pd
import joblib
from app.services.log_service import Anomalie_service
from app.schema.anomalie_schema import CreateAnomalieDto, CreateReportedAnomalieDto
from app.services.mailer_services import Mailer_Service,get_setting
from app.templates.alertHtml import get_alert_email_template
    


anomalie_service = Anomalie_service()
settings = get_setting()
mailer_service = Mailer_Service(settings)
class KernLogProcessor:
    async def get_email_list(self):
        test = await anomalie_service.getAlertReceiver()
        emails = [receiver['email'] for receiver in test if 'email' in receiver and receiver.get('autoSend') == True]
        return emails
    
    def __init__(self, model_path="app/models/kernlog_model.joblib"):
        self.memory_errors = defaultdict(int)
        self.disk_errors = defaultdict(int)
        self.oom_events = []

        self.scaler, self.model = joblib.load(model_path)

        # même regex que le script d'entraînement
        self.kern_regex = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+\d{2}:\d{2}))\s'
            r'(?P<host>\S+)\s+kernel:\s(?P<message>.*)$'
        )
        self.oom_pattern = re.compile(r'Out of memory: Kill process (?P<pid>\d+) \((?P<process>\S+)\)')

    def parse_log(self, line: str):
        match = self.kern_regex.match(line)
        if not match:
            return None

        parsed = match.groupdict()
        ts = self._convert_timestamp(parsed['timestamp'])

        log_entry = {
            "timestamp": ts,
            "host": parsed['host'],
            "message": parsed['message'],
            "raw": line.strip(),
            "event_type": self._classify_event(parsed['message']),
        }

        if log_entry["event_type"] == "oom_kill":
            oom_match = self.oom_pattern.search(parsed['message'])
            if oom_match:
                log_entry.update({
                    "oom_pid": int(oom_match.group('pid')),
                    "oom_process": oom_match.group('process')
                })

        return log_entry

    def _convert_timestamp(self, ts_str):
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).isoformat()
        except:
            return None

    def _classify_event(self, message: str):
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
        return {
            "hour": datetime.fromisoformat(log["timestamp"]).hour if log["timestamp"] else 0,
            "is_error": 1 if log["event_type"] in ("oom_kill", "hardware_error") else 0,
            "is_warning": 1 if log["event_type"] == "hardware_warning" else 0,
            "is_network": 1 if "br-" in log["message"] or "veth" in log["message"] else 0,
            "is_storage": 1 if any(x in log["message"] for x in ["sd", "hd", "nvme"]) else 0,
            "message_length": len(log["message"])
        }
    def _extract_device_from_message(self, message: str) -> str:
        for word in message.split():
            if any(prefix in word for prefix in ["sd", "hd", "nvme"]):
                return word
        return None

    def _extract_source_ip(self, message: str) -> str:
        match = re.search(r'from\s(\d+\.\d+\.\d+\.\d+)', message)
        return match.group(1) if match else "unknown"
        
async def detect_attacks(self, logs, device_name):
    alerts = []

    for log in logs:
        if not log or "event_type" not in log:
            continue

        if log["event_type"] == "oom_kill":
            self.oom_events.append(log)
            if len(self.oom_events) > 2:
                alerts.append({
                    "type": "memory_leak",
                    "count": len(self.oom_events),
                    "last_process": log.get("oom_process"),
                    "timestamp": log["timestamp"]
                })

        elif log["event_type"] == "hardware_error":
            if any(x in log["message"] for x in ["sd", "hd", "nvme"]):
                device = self._extract_device_from_message(log["message"])
                if device:
                    self.disk_errors[device] += 1
                    if self.disk_errors[device] > 3:
                        alerts.append({
                            "type": "disk_failure",
                            "device": device['name'],
                            "count": self.disk_errors[device],
                            "timestamp": log["timestamp"]
                        })

        elif log["event_type"] == "syn_flood":
            alerts.append({
                "type": "syn_flood",
                "source": self._extract_source_ip(log["message"]),
                "timestamp": log["timestamp"],
                "raw": log["raw"]
            })

        elif log["event_type"] == "usb_disconnect":
            if "storage" in log["message"].lower():
                alerts.append({
                    "type": "usb_storage_removed",
                    "timestamp": log["timestamp"]
                })

    if logs:
        filtered_logs = [log for log in logs if log and "event_type" in log]
        df = pd.DataFrame([self.extract_features(log) for log in filtered_logs])
        if not df.empty:
            X = self.scaler.transform(df)
            scores = self.model.decision_function(X)
            for i, log in enumerate(filtered_logs):
                log["anomaly_score"] = float(scores[i])
                log["is_anomaly"] = scores[i] < -0.25
                print(f"kern {log}")
                
                if log['is_anomaly']:
                    await anomalie_service.create_anomalie(
                        CreateAnomalieDto(
                            timestamp=datetime.fromisoformat(log["timestamp"]),
                            host=log["host"],
                            process=log["process"],
                            pid=log.get("pid"),
                            message=log["message"],
                            raw=log["raw"],
                            severity=log.get("severity"),
                            anomaly_score=log["anomaly_score"],
                            is_anomaly=log["is_anomaly"],
                            device_name=device_name
                        ).dict()
                    )
                    for email in await self.get_email_list():
                        html_content = get_alert_email_template(log)
                        await mailer_service.send_email(
                            to=email,
                            subject="🚨 Alerte SentinelAI - Anomalie détectée",
                            html_template=html_content
                        )
    if len(alerts) > 0:
        for alert in alerts:
            await anomalie_service.create_reported_anomalie(
                CreateReportedAnomalieDto(
                    type=alert['type'],
                    count=alert.get('count'),
                    last_process=alert.get('last_process'),
                    timestamp=alert.get('timestamp'),
                    device_name=alert.get('device'),
                    source=alert.get('source'),
                    log=alert.get('raw'),
                ).dict()
            )
            for email in await self.get_email_list():
                html_content = get_alert_email_template(alert)
                await mailer_service.send_email(
                    to=email,
                    subject="🚨 Alerte SentinelAI - Anomalie détectée",
                    html_template=html_content
                )
    return logs, alerts


