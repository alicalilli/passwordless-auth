from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import config

limiter = Limiter(get_remote_address, default_limits=[config.LIMIT_DEFAULT], storage_uri="memory://",
                  headers_enabled=True)


def email_key():
    """Rate-limit key per target account, so many IPs cannot hammer one user."""
    email = (request.form.get("email") or "").strip().lower()
    return f"email:{email}"
