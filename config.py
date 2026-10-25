"""Settings for the passwordless demo. Every value can be overridden with an environment variable."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# WebAuthn relying party. Open the site at exactly this origin (localhost, not 127.0.0.1).
RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = os.environ.get("RP_NAME", "ITSM Passwordless Lab")
PORT = int(os.environ.get("PORT", "5000"))
ORIGIN = os.environ.get("ORIGIN", f"http://localhost:{PORT}")

DATABASE = os.environ.get("DATABASE", os.path.join(BASE_DIR, "instance", "app.db"))
AUTH_LOG = os.environ.get("AUTH_LOG", os.path.join(BASE_DIR, "instance", "auth.log"))

# Emails whose account becomes admin when it signs up.
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "admin@itsm.lab").split(",") if e.strip()}
GROUPS = ["students", "staff", "contractors"]

# Demo mode shows sent e-mails on /dev/outbox instead of using a real mail server.
DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"

# Session lifetimes (seconds)
ANON_SESSION_TTL = 15 * 60          # pre-login session (holds challenges, CSRF token)
IDLE_TIMEOUT = 30 * 60              # logged-in session idle limit
ABSOLUTE_TIMEOUT = 12 * 60 * 60     # logged-in session hard limit
STEP_UP_WINDOW = 10 * 60            # sensitive actions need authentication this recent

# Token lifetimes (seconds)
MAGIC_LINK_TTL = 10 * 60
RESET_LINK_TTL = 15 * 60
SIGNUP_LINK_TTL = 30 * 60
ENROLL_LINK_TTL = 24 * 60 * 60      # admin-issued enrolment link

BACKUP_CODE_COUNT = 10

# Cookies. Browsers treat http://localhost as a secure context, so Secure and __Host- work there.
SESSION_COOKIE = "__Host-sid"
BIND_COOKIE = "__Host-bind"

# Rate limits (flask-limiter syntax)
LIMIT_DEFAULT = "200 per minute"
LIMIT_IP_AUTH = "10 per minute"
LIMIT_EMAIL_LINK = "3 per 15 minutes"
LIMIT_EMAIL_BACKUP = "5 per 15 minutes"
LIMIT_PASSKEY = "20 per minute"
