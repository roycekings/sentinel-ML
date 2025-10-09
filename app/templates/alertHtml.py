from datetime import datetime

def get_alert_email_template(data: dict) -> str:
    return f"""
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Alerte SentinelAI</title>
  <style>
    body {{
      font-family: "Segoe UI", Roboto, Arial, sans-serif;
      background-color: #f6f8fa;
      margin: 0;
      padding: 0;
    }}
    .container {{
      background-color: #ffffff;
      max-width: 600px;
      margin: 40px auto;
      border-radius: 10px;
      box-shadow: 0 4px 10px rgba(0,0,0,0.1);
      overflow: hidden;
    }}
    .header {{
      background-color: #1f2937;
      color: #ffffff;
      padding: 20px;
      text-align: center;
    }}
    .content {{
      padding: 25px;
      color: #333333;
    }}
    .content h2 {{
      color: #1f2937;
      margin-top: 0;
    }}
    .info-table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
    }}
    .info-table th, .info-table td {{
      text-align: left;
      padding: 8px;
      border-bottom: 1px solid #e5e7eb;
    }}
    .info-table th {{
      width: 35%;
      color: #555;
    }}
    .footer {{
      background-color: #f3f4f6;
      padding: 15px;
      text-align: center;
      font-size: 13px;
      color: #777;
    }}
    .badge {{
      display: inline-block;
      background-color: #dc2626;
      color: white;
      padding: 5px 10px;
      border-radius: 5px;
      font-size: 12px;
      text-transform: uppercase;
      margin-top: 5px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚨 Alerte SentinelAI</h1>
      <p>Anomalie détectée sur votre infrastructure</p>
    </div>

    <div class="content">
      <h2>{data.get("message", "Anomalie détectée")}</h2>
      <p>Une anomalie a été détectée et signalée par SentinelAI. Voici les détails :</p>

      <table class="info-table">
        {f"<tr><th>Appareil</th><td>{data['device_name']}</td></tr>" if data.get("device_name") else ""}
        {f"<tr><th>Hôte</th><td>{data['host']}</td></tr>" if data.get("host") else ""}
        {f"<tr><th>Adresse IP</th><td>{data['ip']}</td></tr>" if data.get("ip") else ""}
        {f"<tr><th>Type</th><td>{data['type']}</td></tr>" if data.get("type") else ""}
        {f"<tr><th>Processus</th><td>{data['process']}</td></tr>" if data.get("process") else ""}
        {f"<tr><th>PID</th><td>{data['pid']}</td></tr>" if data.get("pid") else ""}
        {f"<tr><th>Gravité</th><td>{data['severity']}</td></tr>" if data.get("severity") else ""}
        {f"<tr><th>Score d'anomalie</th><td>{data['anomaly_score']}</td></tr>" if data.get("anomaly_score") else ""}
        {f"<tr><th>Est une anomalie</th><td>{data['is_anomaly']}</td></tr>" if data.get("is_anomaly") is not None else ""}
        {f"<tr><th>Occurrences</th><td>{data['count']}</td></tr>" if data.get("count") else ""}
        {f"<tr><th>Utilisateur cible</th><td>{data['target_user']}</td></tr>" if data.get("target_user") else ""}
        {f"<tr><th>Utilisateur tenté</th><td>{data['user_tried']}</td></tr>" if data.get("user_tried") else ""}
        {f"<tr><th>Dernier processus</th><td>{data['last_process']}</td></tr>" if data.get("last_process") else ""}
        {f"<tr><th>Source</th><td>{data['source']}</td></tr>" if data.get("source") else ""}
        {f"<tr><th>Log</th><td><pre style='white-space: pre-wrap; font-size: 13px;'>{data['log']}</pre></td></tr>" if data.get("log") else ""}
        {f"<tr><th>Brut</th><td><pre style='white-space: pre-wrap; font-size: 13px;'>{data['raw']}</pre></td></tr>" if data.get("raw") else ""}
        {f"<tr><th>Horodatage</th><td>{data['timestamp']}</td></tr>" if data.get("timestamp") else ""}
      </table>

      <div style="margin-top: 20px;">
        <span class="badge">ID Anomalie : {data.get("idAnomalies", "N/A")}</span>
      </div>
    </div>

    <div class="footer">
      <p>© {datetime.now().year} SentinelAI — Surveillance intelligente des anomalies réseau et système.</p>
    </div>
  </div>
</body>
</html>
"""
