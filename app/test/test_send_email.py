import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from app.services.mailer_services import Mailer_Service,get_setting

# -----------------------------
# 🔹 TEMPLATE HTML DE L'EMAIL
# -----------------------------
settings = get_setting()
mailer = Mailer_Service(settings)
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
        {f"<tr><th>Score d'anomalie</th><td>{data['anomaly_score']}</td></tr>" if data.get("anomaly_score") else ""}
        {f"<tr><th>Gravité</th><td>{data['severity']}</td></tr>" if data.get("severity") else ""}
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

# -----------------------------
# 🔹 ENVOI DE L'EMAIL
# -----------------------------
def send_email(to_email: str, subject: str, html_content: str):
    # ⚙️ CONFIG SMTP (exemple Gmail)
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = "ton.email@gmail.com"
    SMTP_PASSWORD = "ton_mot_de_passe_ou_app_password"

    # Création du message
    msg = MIMEMultipart("alternative")
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    # Ajout du contenu HTML
    msg.attach(MIMEText(html_content, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
            print(f"✅ Mail envoyé à {to_email}")
    except Exception as e:
        print(f"❌ Erreur d'envoi : {e}")

# -----------------------------
# 🔹 EXEMPLE DE DONNÉES
# -----------------------------
def generate_fake_data():
    return {
        "message": "Tentative de brute force SSH détectée",
        "device_name": "Server-01",
        "host": "ubuntu-prod",
        "ip": "192.168.1.10",
        "type": "Brute Force",
        "process": "sshd",
        "severity": 8,
        "anomaly_score": 0.97,
        "is_anomaly": True,
        "idAnomalies": "ANOM-20251007-001",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

# -----------------------------
# 🚀 MAIN
# -----------------------------
if __name__ == "__main__":
    data = generate_fake_data()
    html_content = get_alert_email_template(data)


    mailer.send_email(
        to='yamenoc3434@gmail.com',
        subject="🚨 Alerte SentinelAI - Anomalie détectée",
        html_template=html_content
    )
