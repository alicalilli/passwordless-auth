import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RP_ID = os.environ.get("RP_ID", "localhost")
RP_NAME = os.environ.get("RP_NAME", "Passwordless Auth")
PORT = int(os.environ.get("PORT", "5000"))
ORIGIN = os.environ.get("ORIGIN", f"http://localhost:{PORT}")

DATABASE = os.environ.get("DATABASE", os.path.join(BASE_DIR, "instance", "app.db"))
AUTH_LOG = os.environ.get("AUTH_LOG", os.path.join(BASE_DIR, "instance", "auth.log"))

ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "itsmlab2test@proton.me").split(",")}
GROUPS = ["students", "staff", "contractors"]

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "jalilliali2004@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").replace(" ", "")
MAIL_FROM = os.environ.get("MAIL_FROM", SMTP_USER)

ANON_SESSION_TTL = 15 * 60
IDLE_TIMEOUT = 30 * 60
ABSOLUTE_TIMEOUT = 12 * 60 * 60
STEP_UP_WINDOW = 10 * 60

MAGIC_LINK_TTL = 10 * 60
RESET_LINK_TTL = 15 * 60
SIGNUP_LINK_TTL = 30 * 60
ENROLL_LINK_TTL = 24 * 60 * 60

BACKUP_CODE_COUNT = 10

SESSION_COOKIE = "__Host-sid"
BIND_COOKIE = "__Host-bind"

LIMIT_DEFAULT = "200 per minute"
LIMIT_IP_AUTH = "10 per minute"
LIMIT_EMAIL_LINK = "3 per 15 minutes"
LIMIT_EMAIL_BACKUP = "5 per 15 minutes"
LIMIT_PASSKEY = "20 per minute"
