import smtplib
import config
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send(receiverEmail, subject, body):
    assert config.SENDER_EMAIL_ADDRESS, 'Sender email address is not configured'
    assert config.SENDER_EMAIL_PASSWORD, 'Sender email password is not configured'
    assert config.SMTP_SERVER_DOMAIN, 'SMTP server domain is not configured'
    assert config.SMTP_SERVER_PORT, 'SMTP server port is not configured'

    try:
        message = MIMEMultipart()
        message['From'] = config.SENDER_EMAIL_ADDRESS
        message['To'] = receiverEmail
        message['Subject'] = subject

        message.attach(MIMEText(body))

        server = smtplib.SMTP(config.SMTP_SERVER_DOMAIN, config.SMTP_SERVER_PORT)
        server.starttls()
        server.login(config.SENDER_EMAIL_ADDRESS, config.SENDER_EMAIL_PASSWORD)
        server.send_message(message)
        server.quit()
    except smtplib.SMTPException as error:
        print(f'[ERROR] Failed to send email: {error}')
        raise Exception('Failed to send email')
    except Exception as error:
        print(f'[ERROR] An unexpected error occurred while sending email: {error}')
        raise error