import logging
import re
from datetime import datetime

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

import config
import db
from extensions import limiter
from security import check_csrf, csrf_token, load_session, log_event, pop_flashes, save_session


class RedactTokens(logging.Filter):
    pattern = re.compile(r"([?&]t=)[^&\s\"]+")

    def filter(self, record):
        record.msg = self.pattern.sub(r"\1[REDACTED]", str(record.msg))
        if record.args:
            record.args = tuple(self.pattern.sub(r"\1[REDACTED]", a) if isinstance(a, str) else a
                                for a in record.args)
        return True


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    db.init_db()
    limiter.init_app(app)
    logging.getLogger("werkzeug").addFilter(RedactTokens())

    from account import bp as account_bp
    from admin import bp as admin_bp
    from auth import bp as auth_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(admin_bp)

    app.teardown_appcontext(db.close_db)

    @app.before_request
    def before():
        if request.endpoint == "static":
            return
        load_session()
        check_csrf()

    @app.after_request
    def after(resp):
        if request.endpoint != "static":
            save_session(resp)
            resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if config.ORIGIN.startswith("https://"):
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(429)
    def too_many(e):
        log_event("rate_limited", "failure", detail=f"path={request.path} limit={e.description}")
        if request.is_json or request.path.startswith("/passkey/"):
            return jsonify(error="Too many attempts. Wait a little and try again."), 429
        return render_template("message.html", title="Too many attempts",
                               message="Slow down. Wait a few minutes and try again."), 429

    @app.errorhandler(HTTPException)
    def http_error(e):
        if request.path.startswith("/passkey/"):
            return jsonify(error=e.name), e.code
        return render_template("message.html", title=f"{e.code} {e.name}", message=e.description), e.code

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token, "user": g.get("user"), "flashes": pop_flashes,
                "sess": g.get("sess")}

    @app.template_filter("dt")
    def dt(ts):
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "never"

    return app


app = create_app()

if __name__ == "__main__":
    if not config.SMTP_PASSWORD:
        import getpass
        config.SMTP_PASSWORD = getpass.getpass(f"App password for {config.SMTP_USER}: ").replace(" ", "").strip()
    print(f"\n  {config.ORIGIN}  (sending from {config.SMTP_USER}, admin: {', '.join(sorted(config.ADMIN_EMAILS))})\n")
    app.run(host="localhost", port=config.PORT, debug=False)
