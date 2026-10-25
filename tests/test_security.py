"""Security test log: every defence is checked by an automated test.
Run:  python -m pytest -v tests/test_security.py
"""
import logging
import re
import secrets
import sqlite3
import statistics
import time
import os

import config
from app import RedactTokens
from conftest import BASE

DBP = os.environ["DATABASE"]


# ------------------------------------------------------------------ helpers
def sql(q, args=()):
    con = sqlite3.connect(DBP); con.row_factory = sqlite3.Row
    rows = con.execute(q, args).fetchall(); con.commit(); con.close()
    return rows


def make_user(app, email, role="user", grp="students", codes=True):
    sql("INSERT INTO users (email, display_name, user_handle, grp, role, created_at) VALUES (?,?,?,?,?,?)",
        (email, email.split("@")[0], secrets.token_bytes(32), grp, role, int(time.time())))
    uid = sql("SELECT id FROM users WHERE email = ?", (email,))[0]["id"]
    out = []
    if codes:
        from security import new_backup_codes
        with app.test_request_context():
            out = new_backup_codes(uid)
    return uid, out


def csrf(client, path="/login"):
    html = client.get(path, base_url=BASE).get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def sid(client):
    c = client.get_cookie(config.SESSION_COOKIE, domain="localhost")
    return c.value if c else None


def last_link(email):
    body = sql("SELECT body FROM outbox WHERE to_email = ? ORDER BY id DESC LIMIT 1", (email,))[0]["body"]
    return re.search(r"/auth/link\?t=([\w-]+)", body).group(1)


def magic_login(client, email):
    tok = csrf(client)
    client.post("/auth/magic", data={"email": email, "csrf_token": tok}, base_url=BASE)
    t = last_link(email)
    client.get(f"/auth/link?t={t}", base_url=BASE)
    return client.post("/auth/link", data={"t": t, "csrf_token": csrf(client)}, base_url=BASE), t


# ------------------------------------------------------------------ cookies and headers
def test_cookie_flags(client):
    r = client.get("/login", base_url=BASE)
    cookie = r.headers["Set-Cookie"]
    assert cookie.startswith("__Host-sid=")
    for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        assert flag in cookie
    assert "Domain=" not in cookie and "Expires" not in cookie and "Max-Age" not in cookie


def test_security_headers(client):
    h = client.get("/login", base_url=BASE).headers
    assert "script-src 'self'" in h["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["Referrer-Policy"] == "same-origin"
    assert h["Cache-Control"] == "no-store"


# ------------------------------------------------------------------ CSRF
def test_post_without_csrf_token_is_rejected(client):
    client.get("/login", base_url=BASE)
    r = client.post("/auth/magic", data={"email": "a@itsm.lab"}, base_url=BASE)
    assert r.status_code == 403


def test_post_from_foreign_origin_is_rejected(client):
    tok = csrf(client)
    r = client.post("/auth/magic", data={"email": "a@itsm.lab", "csrf_token": tok}, base_url=BASE,
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


# ------------------------------------------------------------------ account enumeration
def test_magic_link_same_answer_for_known_and_unknown(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client)
    a = client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    b = client.post("/auth/magic", data={"email": "nosuchuser@itsm.lab", "csrf_token": tok}, base_url=BASE)
    assert a.status_code == b.status_code == 200
    strip = lambda r: re.sub(r'content="[^"]+"|value="[^"]+"', "", r.get_data(as_text=True))
    assert strip(a) == strip(b)


def test_signup_same_answer_for_existing_account(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client, "/signup")
    a = client.post("/signup", data={"email": "ona@itsm.lab", "name": "x", "csrf_token": tok}, base_url=BASE)
    b = client.post("/signup", data={"email": "new@itsm.lab", "name": "x", "csrf_token": tok}, base_url=BASE)
    strip = lambda r: re.sub(r'content="[^"]+"|value="[^"]+"', "", r.get_data(as_text=True))
    assert a.status_code == b.status_code == 200 and strip(a) == strip(b)


def test_backup_code_timing_does_not_reveal_accounts(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client, "/recover")

    def timed(email):
        t = time.perf_counter()
        r = client.post("/recover", data={"email": email, "code": "aaaaa-aaaaa", "csrf_token": tok}, base_url=BASE)
        return time.perf_counter() - t, r

    known, unknown = [], []
    for _ in range(2):                       # stays under the per-account limit (5 per 15 min)
        k, rk = timed("ona@itsm.lab"); u, ru = timed("nosuchuser@itsm.lab")
        known.append(k); unknown.append(u)
    assert rk.status_code == ru.status_code == 401
    ratio = statistics.mean(known) / statistics.mean(unknown)
    print(f"\n  backup-code check: known {statistics.mean(known)*1000:.0f} ms, unknown "
          f"{statistics.mean(unknown)*1000:.0f} ms, ratio {ratio:.2f}")
    assert 0.7 < ratio < 1.4


# ------------------------------------------------------------------ rate limiting
def test_rate_limit_per_account(client):
    tok = csrf(client)
    codes = [client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE).status_code
             for _ in range(5)]
    print("\n  per-account:", codes)
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_rate_limit_per_ip(client):
    tok = csrf(client)
    codes = [client.post("/auth/magic", data={"email": f"u{i}@itsm.lab", "csrf_token": tok},
                         base_url=BASE).status_code for i in range(12)]
    print("\n  per-IP:", codes)
    assert codes[:10] == [200] * 10 and codes[10] == 429


def test_rate_limited_attempts_are_logged(client):
    tok = csrf(client)
    for _ in range(5):
        client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    assert sql("SELECT COUNT(*) AS n FROM events WHERE event = 'rate_limited'")[0]["n"] >= 1


# ------------------------------------------------------------------ magic links
def test_magic_link_is_single_use(app, client):
    make_user(app, "ona@itsm.lab")
    r, t = magic_login(client, "ona@itsm.lab")
    assert r.status_code == 302 and r.headers["Location"].endswith("/account")
    again = client.post("/auth/link", data={"t": t, "csrf_token": csrf(client, "/account")}, base_url=BASE)
    assert again.headers["Location"].endswith("/login")
    assert sql("SELECT detail FROM events WHERE event='link_rejected'")[-1]["detail"] == "already_used"


def test_magic_link_expires(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client)
    client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    t = last_link("ona@itsm.lab")
    sql("UPDATE tokens SET expires_at = ?", (int(time.time()) - 1,))
    r = client.post("/auth/link", data={"t": t, "csrf_token": tok}, base_url=BASE)
    assert r.headers["Location"].endswith("/login")
    assert sql("SELECT detail FROM events WHERE event='link_rejected'")[-1]["detail"] == "expired"


def test_magic_link_bound_to_requesting_browser(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client)
    client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    t = last_link("ona@itsm.lab")
    attacker = app.test_client()
    r = attacker.post("/auth/link", data={"t": t, "csrf_token": csrf(attacker)}, base_url=BASE)
    assert r.headers["Location"].endswith("/login")
    assert sql("SELECT detail FROM events WHERE event='link_rejected'")[-1]["detail"] == "other_browser"


def test_only_token_hash_is_stored(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client)
    client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    t = last_link("ona@itsm.lab")
    stored = [r["token_hash"] for r in sql("SELECT token_hash FROM tokens")]
    assert t not in stored and len(stored[0]) == 64


def test_link_token_redacted_from_access_log():
    rec = logging.LogRecord("werkzeug", logging.INFO, "", 0, '%s - - "%s" %s',
                            ("127.0.0.1", "GET /auth/link?t=SECRET123 HTTP/1.1", "200"), None)
    RedactTokens().filter(rec)
    assert "SECRET123" not in rec.getMessage() and "[REDACTED]" in rec.getMessage()


def test_get_does_not_consume_link(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client)
    client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    t = last_link("ona@itsm.lab")
    for _ in range(3):                                  # e.g. a mail scanner pre-fetching the link
        client.get(f"/auth/link?t={t}", base_url=BASE)
    assert sql("SELECT used_at FROM tokens")[0]["used_at"] is None


# ------------------------------------------------------------------ sessions
def test_session_id_rotates_at_login_and_old_id_is_dead(app, client):
    make_user(app, "ona@itsm.lab")
    client.get("/login", base_url=BASE)
    before = sid(client)
    magic_login(client, "ona@itsm.lab")
    after = sid(client)
    assert before and after and before != after
    replay = app.test_client()
    replay.set_cookie(config.SESSION_COOKIE, before, domain="localhost")
    r = replay.get("/account", base_url=BASE)
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_logout_kills_session_server_side(app, client):
    make_user(app, "ona@itsm.lab")
    magic_login(client, "ona@itsm.lab")
    stolen = sid(client)
    client.post("/logout", data={"csrf_token": csrf(client, "/account")}, base_url=BASE)
    replay = app.test_client()
    replay.set_cookie(config.SESSION_COOKIE, stolen, domain="localhost")
    assert replay.get("/account", base_url=BASE).status_code == 302


def test_idle_timeout(app, client):
    make_user(app, "ona@itsm.lab")
    magic_login(client, "ona@itsm.lab")
    sql("UPDATE sessions SET last_seen = last_seen - ?", (config.IDLE_TIMEOUT + 1,))
    assert client.get("/account", base_url=BASE).status_code == 302


def test_session_id_stored_hashed(app, client):
    make_user(app, "ona@itsm.lab")
    magic_login(client, "ona@itsm.lab")
    assert sid(client) not in [r["id_hash"] for r in sql("SELECT id_hash FROM sessions")]


# ------------------------------------------------------------------ backup codes
def test_backup_code_works_once(app, client):
    _, codes = make_user(app, "ona@itsm.lab")
    tok = csrf(client, "/recover")
    r1 = client.post("/recover", data={"email": "ona@itsm.lab", "code": codes[0], "csrf_token": tok}, base_url=BASE)
    assert r1.status_code == 302
    c2 = app.test_client(); tok2 = csrf(c2, "/recover")
    r2 = c2.post("/recover", data={"email": "ona@itsm.lab", "code": codes[0], "csrf_token": tok2}, base_url=BASE)
    assert r2.status_code == 401


def test_backup_codes_stored_as_argon2(app):
    make_user(app, "ona@itsm.lab")
    h = sql("SELECT code_hash FROM backup_codes")[0]["code_hash"]
    assert h.startswith("$argon2id$")


# ------------------------------------------------------------------ step-up and access control
def test_magic_link_session_cannot_open_admin(app, client):
    make_user(app, "boss@itsm.lab", role="admin")
    magic_login(client, "boss@itsm.lab")
    r = client.get("/admin", base_url=BASE)
    assert r.status_code == 302 and "/reauth" in r.headers["Location"]


def test_magic_link_session_cannot_change_credentials(app, client):
    make_user(app, "ona@itsm.lab")
    magic_login(client, "ona@itsm.lab")
    r = client.post("/account/backup-codes", data={"csrf_token": csrf(client, "/account")}, base_url=BASE)
    assert r.status_code == 302 and "/reauth" in r.headers["Location"]


def test_cannot_delete_another_users_passkey(app, client):
    other, _ = make_user(app, "other@itsm.lab")
    sql("INSERT INTO passkeys (user_id, credential_id, public_key, name, created_at) VALUES (?,?,?,?,?)",
        (other, b"cred-x", b"pk", "theirs", 0))
    pk_id = sql("SELECT id FROM passkeys")[0]["id"]
    _, codes = make_user(app, "ona@itsm.lab")
    tok = csrf(client, "/recover")
    client.post("/recover", data={"email": "ona@itsm.lab", "code": codes[0], "csrf_token": tok}, base_url=BASE)
    r = client.post(f"/account/passkeys/{pk_id}/delete", data={"csrf_token": csrf(client, "/account")}, base_url=BASE)
    assert r.status_code == 404 and sql("SELECT COUNT(*) AS n FROM passkeys")[0]["n"] == 1


def test_disabled_account_cannot_sign_in(app, client):
    make_user(app, "ona@itsm.lab")
    sql("UPDATE users SET status = 'disabled'")
    tok = csrf(client)
    r = client.post("/auth/magic", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    assert r.status_code == 200                                   # same generic answer on screen
    body = sql("SELECT body FROM outbox ORDER BY id DESC LIMIT 1")[0]["body"]
    assert "/auth/link" not in body                               # but no usable link is sent


def test_reset_needs_backup_code_not_just_email(app, client):
    make_user(app, "ona@itsm.lab")
    tok = csrf(client, "/reset")
    client.post("/reset", data={"email": "ona@itsm.lab", "csrf_token": tok}, base_url=BASE)
    t = last_link("ona@itsm.lab")
    r = client.post("/auth/link", data={"t": t, "csrf_token": tok}, base_url=BASE)
    assert r.headers["Location"].endswith("/reset/confirm")
    r = client.post("/reset/confirm", data={"code": "wrong-codex", "csrf_token": tok}, base_url=BASE)
    assert r.status_code == 401
    assert client.get("/account", base_url=BASE).status_code == 302      # still not signed in


def test_open_redirect_blocked():
    from security import safe_next
    for bad in ("//evil.com", "https://evil.com", "http:/evil.com", "javascript:alert(1)"):
        assert safe_next(bad) is None
    assert safe_next("/account") == "/account"
