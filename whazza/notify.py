import threading
import requests
import logging
import smtplib

from email.mime.text import MIMEText
from .config import server_config


config = server_config()


def notify(msg: str) -> None:
    if config['notification_url'] is not None:
        logging.info("Notify: {}".format(msg))

        payload = config['notification_base_msg'].copy()
        payload['message'] = msg

        try:
            requests.post(config['notification_url'], data=payload)
        except Exception as e:
            logging.warn("Exception sending notification: {}".format(e))

    if config['notification_mail'] is not None:
        mail_thread = threading.Thread(target=notify_email, args=(msg,))
        mail_thread.start()


def notify_email(msg: str) -> None:
    logging.debug('notifying {}'.format(config['notification_mail']))

    msg = MIMEText(msg)
    msg['Subject'] = 'Notification'
    msg['From'] = config['mail_from']
    msg['To'] = config['notification_mail']

    try:
        with smtplib.SMTP_SSL(config['smtp_host']) as s:
            if config['smtp_user'] is not None:
                s.login(config['smtp_user'], config['smtp_password'])
            s.send_message(msg)
    except Exception as e:
        logging.warning("Couldn't send mail", e)
