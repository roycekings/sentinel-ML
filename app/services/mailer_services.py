import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pydantic_settings import BaseSettings
from pydantic import EmailStr
import traceback

# -----------------------------
# CONFIGURATION
# -----------------------------
class Setting(BaseSettings):
    MAIL_USER: str ="zeparas34@gmail.com"
    MAIL_PASS: str= "mmka mjbx xrmu nvre"
    MAIL_HOST: str = "smtp.gmail.com"
    MAIL_PORT: int = 587

    class Config:
        env_file = ".env"  # ⚠️ Assure-toi que .env est présent et contient MAIL_USER et MAIL_PASS

def get_setting():
    return Setting()  # renvoie une instance réelle de Setting

# -----------------------------
# SERVICE MAIL
# -----------------------------
class Mailer_Service:
    def __init__(self, settings: Setting):
        self.settings = settings

    def send_email(self, to: EmailStr, subject: str, html_template: str):
        """Envoie un email HTML via SMTP"""
        msg = MIMEMultipart()
        msg["From"] = self.settings.MAIL_USER
        msg["To"] = to
        msg["Subject"] = subject

        msg.attach(MIMEText(html_template, "html"))

        try:
            with smtplib.SMTP(self.settings.MAIL_HOST, self.settings.MAIL_PORT) as server:
                server.starttls()
                server.login(self.settings.MAIL_USER, self.settings.MAIL_PASS)
                server.send_message(msg)
                print(f"✅ Mail envoyé à {to}")
        except Exception as e:
            traceback.print_exc()
            raise Exception(f"Erreur envoi mail: {e}")
