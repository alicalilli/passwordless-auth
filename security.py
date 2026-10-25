import functools
import hashlib
import hmac
import json
import secrets
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from flask import abort, g, redirect, request, url_for

import config
import mailer
from db import execute, now, query

ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-backup-code")

STRONG_METHODS = {"passkey", "backup_code", "signup_link", "enroll_link", "reset"}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def log_event(event, outcome="success", user_id=None, email=None, detail=None):
    ip = request.remote_addr if request else None
    execute("INSERT INTO events (ts, event, outcome, user_id, email, ip, detail) VALUES (?,?,?,?,?,?,?)",
            (now(), event, outcome, user_id, email, ip, detail))
    line = {"ts": now(), "event": event, "outcome": outcome, "user_id": user_id,
            "email": email, "ip": ip, "ua": request.headers.get("User-Agent", "")[:120] if request else None,
            "detail": detail}
    with open(config.AUTH_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


def send_mail(to, subject, body):
    mailer.deliver(to, subject, body)


def _new_session_row(user_id=None, auth_method=None):
    raw = secrets.token_urlsafe(32)
    t = now()
    data = {"csrf": secrets.token_urlsafe(32)}
    execute("INSERT INTO sessions (id_hash, user_id, data, auth_method, auth_at, created_at, last_seen, ip, user_agent)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (sha256(raw), user_id, json.dumps(data), auth_method, t if user_id else None, t, t,
             request.remote_addr, request.headers.get("User-Agent", "")[:200]))
    g.sess = {"id_hash": sha256(raw), "user_id": user_id, "data": data, "auth_method": auth_method,
              "auth_at": t if user_id else None, "created_at": t}
    g.new_cookie = raw
    g.sess_dirty = False


def load_session():
    g.sess, g.user, g.new_cookie, g.clear_cookie, g.sess_dirty = None, None, None, False, False
    raw = request.cookies.get(config.SESSION_COOKIE)
    if not raw:
        return
    row = query("SELECT * FROM sessions WHERE id_hash = ?", (sha256(raw),), one=True)
    if row is None:
        g.clear_cookie = True
        return
    t = now()
    if row["user_id"] is None:
        expired = t - row["created_at"] > config.ANON_SESSION_TTL
    else:
        expired = (t - row["last_seen"] > config.IDLE_TIMEOUT or
                   t - row["created_at"] > config.ABSOLUTE_TIMEOUT)
    user = None
    if not expired and row["user_id"] is not None:
        user = query("SELECT * FROM users WHERE id = ?", (row["user_id"],), one=True)
        if user is None or user["status"] != "active":
            expired = True
    if expired:
        execute("DELETE FROM sessions WHERE id_hash = ?", (row["id_hash"],))
        g.clear_cookie = True
        return
    g.sess = {"id_hash": row["id_hash"], "user_id": row["user_id"], "data": json.loads(row["data"]),
              "auth_method": row["auth_method"], "auth_at": row["auth_at"], "created_at": row["created_at"]}
    g.user = user
    if user is not None:
        execute("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", (t, row["id_hash"]))


def ensure_session():
    if g.get("sess") is None:
        _new_session_row()
    return g.sess


def sess_get(key, default=None):
    return (g.sess or {}).get("data", {}).get(key, default)


def sess_set(key, value):
    ensure_session()
    g.sess["data"][key] = value
    g.sess_dirty = True


def sess_pop(key):
    if g.sess and key in g.sess["data"]:
        g.sess_dirty = True
        return g.sess["data"].pop(key)
    return None


def save_session(response):
    if g.get("sess") and g.get("sess_dirty"):
        execute("UPDATE sessions SET data = ? WHERE id_hash = ?", (json.dumps(g.sess["data"]), g.sess["id_hash"]))
    if g.get("new_cookie"):
        response.set_cookie(config.SESSION_COOKIE, g.new_cookie, httponly=True, secure=True,
                            samesite="Lax", path="/")
    elif g.get("clear_cookie"):
        response.delete_cookie(config.SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="Lax")
    if g.get("new_bind"):
        response.set_cookie(config.BIND_COOKIE, g.new_bind, httponly=True, secure=True, samesite="Lax",
                            path="/", max_age=config.RESET_LINK_TTL)
    return response


def start_authenticated_session(user, method):
    old = g.sess["id_hash"] if g.get("sess") else None
    if old:
        execute("DELETE FROM sessions WHERE id_hash = ?", (old,))
    _new_session_row(user["id"], method)
    g.user = user
    log_event("session_created", user_id=user["id"], email=user["email"],
              detail=f"method={method} rotated_from={'yes' if old else 'none'}")


def end_session():
    if g.get("sess"):
        execute("DELETE FROM sessions WHERE id_hash = ?", (g.sess["id_hash"],))
    g.sess, g.user, g.new_cookie, g.clear_cookie = None, None, None, True


def revoke_user_sessions(user_id, keep_current=False):
    if keep_current and g.get("sess"):
        cur = execute("DELETE FROM sessions WHERE user_id = ? AND id_hash != ?", (user_id, g.sess["id_hash"]))
    else:
        cur = execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return cur.rowcount


def flash(message, category="ok"):
    msgs = sess_get("_flash", []) if g.get("sess") else []
    msgs.append([category, message])
    sess_set("_flash", msgs)


def pop_flashes():
    return sess_pop("_flash") or []


def csrf_token():
    ensure_session()
    return g.sess["data"]["csrf"]


def check_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    origin = request.headers.get("Origin")
    if origin and origin != config.ORIGIN:
        log_event("csrf_blocked", "failure", detail=f"bad origin {origin}")
        abort(403)
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = sess_get("csrf")
    if not expected or not hmac.compare_digest(sent, expected):
        log_event("csrf_blocked", "failure", detail=f"path={request.path}")
        abort(403)


def _bind_value():
    raw = request.cookies.get(config.BIND_COOKIE) or g.get("new_bind")
    if not raw:
        raw = secrets.token_urlsafe(32)
        g.new_bind = raw
    return raw


def issue_token(purpose, email, ttl, payload=None, bind=True):
    raw = secrets.token_urlsafe(32)
    bind_hash = sha256(_bind_value()) if bind else None
    t = now()
    execute("INSERT INTO tokens (token_hash, purpose, email, payload, bind_hash, created_at, expires_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (sha256(raw), purpose, email, json.dumps(payload) if payload else None, bind_hash, t, t + ttl))
    return raw


def consume_token(raw):
    if not raw or len(raw) > 100:
        return None, "missing"
    row = query("SELECT * FROM tokens WHERE token_hash = ?", (sha256(raw),), one=True)
    if row is None:
        return None, "unknown"
    if row["used_at"] is not None:
        return None, "already_used"
    if now() > row["expires_at"]:
        return None, "expired"
    if row["bind_hash"]:
        bind = request.cookies.get(config.BIND_COOKIE, "")
        if not hmac.compare_digest(sha256(bind), row["bind_hash"]):
            return None, "other_browser"
    cur = execute("UPDATE tokens SET used_at = ? WHERE id = ? AND used_at IS NULL", (now(), row["id"]))
    if cur.rowcount != 1:
        return None, "already_used"
    return row, None


def invalidate_tokens(email, purposes=None):
    if purposes:
        marks = ",".join("?" * len(purposes))
        execute(f"UPDATE tokens SET used_at = ? WHERE email = ? AND used_at IS NULL AND purpose IN ({marks})",
                (now(), email, *purposes))
    else:
        execute("UPDATE tokens SET used_at = ? WHERE email = ? AND used_at IS NULL", (now(), email))


def link(raw):
    return f"{config.ORIGIN}{url_for('auth.link_landing')}?t={raw}"


ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def new_backup_codes(user_id):
    execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    codes = []
    for _ in range(config.BACKUP_CODE_COUNT):
        c = "".join(secrets.choice(ALPHABET) for _ in range(10))
        c = f"{c[:5]}-{c[5:]}"
        codes.append(c)
        execute("INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?,?,?)",
                (user_id, ph.hash(c), now()))
    return codes


def check_backup_code(user, code):
    code = (code or "").strip().lower().replace(" ", "")
    if len(code) == 10:
        code = f"{code[:5]}-{code[5:]}"
    rows = list(query("SELECT * FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
                      (user["id"],))) if user else []
    hit = None
    for i in range(config.BACKUP_CODE_COUNT):
        stored = rows[i]["code_hash"] if i < len(rows) else DUMMY_HASH
        try:
            if ph.verify(stored, code) and i < len(rows) and hit is None:
                hit = rows[i]
        except (VerificationError, InvalidHashError):
            pass
    if hit is not None:
        cur = execute("UPDATE backup_codes SET used_at = ? WHERE id = ? AND used_at IS NULL", (now(), hit["id"]))
        if cur.rowcount != 1:
            return False
        return True
    return False


def remaining_backup_codes(user_id):
    return query("SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
                 (user_id,), one=True)["n"]


def safe_next(target):
    if not target:
        return None
    p = urlparse(target)
    if p.scheme or p.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


def login_required(view):
    @functools.wraps(view)
    def wrapper(*a, **kw):
        if g.get("user") is None:
            return redirect(url_for("auth.login"))
        return view(*a, **kw)
    return wrapper


def recent_strong_auth(passkey_only=False):
    s = g.get("sess") or {}
    if not s.get("auth_at") or now() - s["auth_at"] > config.STEP_UP_WINDOW:
        return False
    if passkey_only:
        return s.get("auth_method") == "passkey"
    return s.get("auth_method") in STRONG_METHODS


def step_up_required(passkey_only=False):
    def deco(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if g.get("user") is None:
                return redirect(url_for("auth.login"))
            if not recent_strong_auth(passkey_only):
                nxt = request.path if request.method == "GET" else url_for("account.home")
                return redirect(url_for("auth.reauth", next=nxt, pk=1 if passkey_only else 0))
            return view(*a, **kw)
        return wrapper
    return deco


def admin_required(view):
    @functools.wraps(view)
    @step_up_required(passkey_only=True)
    def wrapper(*a, **kw):
        if g.user["role"] != "admin":
            log_event("admin_access_denied", "failure", user_id=g.user["id"], email=g.user["email"])
            abort(403)
        return view(*a, **kw)
    return wrapper
