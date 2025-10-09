import re
from datetime import datetime
import pandas as pd
from collections import defaultdict
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
import json
import numpy as np
import joblib
import logging
import traceback
from app.services.log_service import Anomalie_service
from app.schema.anomalie_schema import CreateAnomalieDto,CreateReportedAnomalieDto
from app.services.mailer_services import Mailer_Service,get_setting
from app.templates.alertHtml import get_alert_email_template

anomalie_service = Anomalie_service()
settings = get_setting()
mailer_service = Mailer_Service(settings)
logger = logging.getLogger(__name__)


class SyslogProcessor:

    async def get_email_list(self):
        test = await anomalie_service.getAlertReceiver()
        emails = [receiver['email'] for receiver in test if 'email' in receiver and receiver.get('autoSend') == True]
        return emails

    def __init__(self, model_path="app/models/sysLog_model.joblib"):
        self.ssh_attempts = defaultdict(int)
        self.ip_activity = defaultdict(int)
        self.scaler, self.model = joblib.load(model_path)

        self.syslog_pattern = re.compile(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2})\s"
            r"(?P<host>\S+)\s(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s(?P<message>.*)$"
        )
        self.ssh_failed_pattern = re.compile(
            r"Failed password for (?P<user>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
        )

    def parse_log(self, line):

        match = self.syslog_pattern.match(line)
        if not match:
            return None

        g = match.groupdict()
        try:
            timestamp = datetime.fromisoformat(g['timestamp'].replace("Z", "+00:00"))
            ts_iso = timestamp.isoformat()
        except Exception as e:
            logger.error(f"❌ Erreur dans la callback RabbitMQ: {type(e).__name__} - {e}")
            traceback.print_exc()

        base_log = {
            "timestamp": ts_iso,
            "host": g['host'],
            "process": g['process'],
            "pid": int(g['pid']) if g['pid'] else None,
            "message": g['message'],
            "raw": line,
            "severity": self._detect_severity(g['message'])
        }

        if base_log["process"] == "sshd" and "Failed password" in base_log["message"]:
            ssh_match = self.ssh_failed_pattern.search(base_log["message"])
            if ssh_match:
                ssh = ssh_match.groupdict()
                base_log.update({
                    "auth_user": ssh.get('user'),
                    "source_ip": ssh.get('source_ip'),
                    "port": int(ssh.get('port'))
                })

        return base_log

    def _detect_severity(self, msg: str) -> int:
        msg = msg.lower()
        if "error" in msg: return 3
        if "warn" in msg or "fail" in msg: return 2
        return 1

    def extract_features(self, log):
        try:
                return {
                "hour": datetime.fromisoformat(log["timestamp"]).hour if log["timestamp"] else 0,
                "severity": log.get("severity", 1),
                "msg_length": len(log.get("message", "")),
                "is_ssh": 1 if log.get("process") == "sshd" else 0,
                "is_cron": 1 if log.get("process") == "CRON" else 0,
                "is_auth_failure": 1 if "Failed password" in log.get("message", "") else 0
            }
        except Exception as e:
            traceback.print_exc()

    async def detect_attacks(self, logs,device_name):
        try:
            alerts = []


            # 🧼 Ne garder que les logs valides
            valid_logs = [log for log in logs if log is not None]

            for log in valid_logs:
                if log.get("process") == "sshd" and "Failed password" in log.get("message", ""):
                    ip = log.get("source_ip")
                    if ip:
                        self.ssh_attempts[ip] += 1
                        if self.ssh_attempts[ip] > 5:
                            alerts.append({
                                "type": "brute_force",
                                "ip": ip,
                                "count": self.ssh_attempts[ip],
                                "log": log
                            })

                if log.get("process") == "kernel" and "SYN" in log.get("message", ""):
                    self.ip_activity[log.get("host")] += 1
                    if self.ip_activity[log.get("host")] > 50:
                        alerts.append({
                            "type": "port_scan",
                            "host": log.get("host"),
                            "count": self.ip_activity[log.get("host")],
                            "log": log
                        })
            if valid_logs:
                
                try:
                    
                    df = pd.DataFrame([self.extract_features(log) for log in valid_logs])
                    if not df.empty:
                        X = self.scaler.transform(df)
                        scores = self.model.decision_function(X)

                        for i, log in enumerate(valid_logs):
                            log["anomaly_score"] = float(scores[i])
                            log["is_anomaly"] = scores[i] < -0.2
                            print(f"syslog {log}")
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
                                    
                            

                except Exception as e:
                    logger.error(f"❌ Erreur lors de l'extraction des features ou scoring : {type(e).__name__} - {e}")
                    traceback.print_exc()
            if len(alerts) > 0:
                for alert in alerts:
                    await anomalie_service.create_reported_anomalie(
                        CreateReportedAnomalieDto(
                            type=alert['type'],
                            # host=alert['log'].get("host"),
                            host=alert.get("host") or None,
                            count=alert['count'],
                            # log=alert['log'].get("raw"),
                            log = alert.get('log') or None,
                        ).dict()
                    )
                    for email in await self.get_email_list():
                        html_content = get_alert_email_template(alert)
                        await mailer_service.send_email(
                            to=email,
                            subject="🚨 Alerte SentinelAI - Anomalie détectée",
                            html_template=html_content
                                    )
            
           
            return valid_logs, alerts
        except Exception as e:
            traceback.print_exc()
           


        

