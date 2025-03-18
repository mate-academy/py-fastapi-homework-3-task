import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional


def send_email(
        subject: str,
        body: str,
        to_email: str,
        from_email: str,
        smtp_server: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        html: Optional[bool] = False
) -> None:
    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject

    if html:
        msg.attach(MIMEText(body, "html"))
    else:
        msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)

        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()

        print("Email has been successfully sent!")

    except Exception as e:
        print(f"Error when sending email: {e}")
