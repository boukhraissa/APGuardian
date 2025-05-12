import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(subject, body, to_email):
    sender_email = "abdelhamida880@gmail.com"
    sender_password = "byjd xjum alel lhzu "  # Use an App Password here

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            print("[+] Email alert sent successfully!")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")

subject = send_email_alert(
    subject="🚨 Deauth Attack Detected!",
    body="NetDefender detected a deauthentication attack on your access point.",
    to_email="abdelhamid.irk@gmail.com"
)
