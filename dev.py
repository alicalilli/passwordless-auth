"""Demo-only mailbox. Replaces a real SMTP server so the live demo needs no e-mail account.
Disabled with DEMO_MODE=0. In production this page must not exist."""
import re

from flask import Blueprint, render_template
from markupsafe import Markup, escape

from db import query

bp = Blueprint("dev", __name__, url_prefix="/dev")
URL = re.compile(r"(https?://[^\s]+)")


@bp.get("/outbox")
def outbox():
    mails = query("SELECT * FROM outbox ORDER BY id DESC LIMIT 30")
    rendered = [dict(m, html=Markup(URL.sub(r'<a href="\1">\1</a>', str(escape(m["body"]))).replace("\n", "<br>")))
                for m in mails]
    return render_template("outbox.html", mails=rendered)
