import json
import smtplib
import ssl
import threading
from email.message import EmailMessage
from html import escape

import config


def _html(body):
    parts = []
    for line in escape(body).split("\n"):
        if line.startswith(("http://", "https://")):
            parts.append(f'<p><a href="{line}" style="display:inline-block;padding:10px 18px;background:#3b5bdb;'
                         f'color:#fff;border-radius:8px;text-decoration:none;font-weight:600">Continue</a></p>'
                         f'<p style="font-size:12px;color:#667085">{line}</p>')
        elif line:
            parts.append(f"<p>{line}</p>")
    return ('<div style="font-family:Segoe UI,Arial,sans-serif;font-size:15px;color:#1d2433;max-width:520px">'
            f'<h2 style="font-size:18px">{escape(config.RP_NAME)}</h2>{"".join(parts)}</div>')


def _message(to, subject, body):
    msg = EmailMessage()
    msg["From"] = f"{config.RP_NAME} <{config.MAIL_FROM}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    msg.add_alternative(_html(body), subtype="html")
    return msg


def _send(to, subject, body):
    msg = _message(to, subject, body)
    ctx = ssl.create_default_context()
    try:
        try:
            with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20) as s:
                s.starttls(context=ctx)
                s.login(config.SMTP_USER, config.SMTP_PASSWORD)
                s.send_message(msg)
        except smtplib.SMTPAuthenticationError:
            raise
        except OSError:
            with smtplib.SMTP_SSL(config.SMTP_HOST, 465, timeout=20, context=ctx) as s:
                s.login(config.SMTP_USER, config.SMTP_PASSWORD)
                s.send_message(msg)
        print(f"[mail] sent to {to}: {subject}", flush=True)
    except Exception as exc:
        print(f"[mail] failed to {to}: {type(exc).__name__}: {exc}", flush=True)
        with open(config.AUTH_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"event": "mail_failed", "outcome": "failure", "email": to,
                                "detail": f"{type(exc).__name__}: {str(exc)[:150]}"}) + "\n")


def deliver(to, subject, body):
    threading.Thread(target=_send, args=(to, subject, body), daemon=True).start()
