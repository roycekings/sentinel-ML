import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi import Depends, HTTPException
from pydantic import BaseSettings, EmailStr
import traceback

class Setting(BaseSettings):
    MAIL_USER: str
    MAIL_PASS: str
    MAIL_HOST: str = "smtp.gmail.com"
    MAIL_PORT: int = 587
    
    class config:
        env_file = ".env"

def get_setting():
    return Setting()

class Mailer_Service:
    def __init__(self, settings: Setting = Depends(get_setting)):
        self.settings = settings

    def send_email(self, to: EmailStr, subject: str, html_template: str):
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
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=str(e))
