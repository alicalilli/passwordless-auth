# Passwordless Lab: passkeys + e-mail magic links

ITSM Practical Work 2 (Web authentication security). Topic: **Passwordless authentication**.
No password is ever created, sent or stored.

## What it does

| Feature | How |
|---|---|
| Main login | **Passkey** (WebAuthn): Windows Hello, fingerprint, phone, security key. Usernameless, user verification required. The server stores only the public key. |
| Fallback login | **E-mail magic link**: single use, 10 min expiry, only the SHA-256 hash is stored, bound to the browser that asked for it. This gives a *low-assurance* session that cannot change credentials or open the admin area. |
| Backup method (extra 1) | 10 one-time **backup codes** (Argon2id), plus a second passkey. |
| Credential reset (extra 2) | Reset link **and** a backup code. It wipes every passkey, code, session and pending link, then the user registers a new passkey. |
| Central revocation (extra 3) | **Admin page**: invite users, sign out, revoke and reset, or disable one user or a whole group (typed confirmation). Every action is logged. |

### Defences
- Session rotation at every login and step-up, server-side sessions (stored hashed), logout kills the session, 30 min idle and 12 h absolute timeout
- Cookies: `__Host-sid; Secure; HttpOnly; SameSite=Lax; Path=/`, with no Domain and no expiry
- CSRF token on every POST plus an Origin check
- Rate limits per IP (10/min) and per account (3 links or 5 codes per 15 min)
- No account enumeration: same screen for known and unknown e-mails, and constant work for backup codes (always 10 Argon2 checks)
- Step-up: credential changes need authentication with a passkey or backup code within the last 10 minutes; the admin area needs a fresh passkey
- Magic-link GET never consumes the token (mail scanners), the token is redacted from the access log, and Referrer-Policy is set
- CSP `script-src 'self'`, X-Frame-Options DENY, nosniff, no-store
- Notification e-mails on new sign-in by link, new passkey, backup code used and reset
- Audit log of every authentication event in the DB and in `instance/auth.log` (JSON lines for a SIEM)

## Run it (Windows)

```powershell
cd passwordless-auth
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000**. Use `localhost`, not `127.0.0.1`, because passkeys are tied to the domain name.
Use Chrome or Edge. Windows Hello creates the passkey.

**Demo e-mail:** there is no real mail server. Every e-mail appears at **http://localhost:5000/dev/outbox**
("Inbox (demo)" in the menu) and in the terminal.

**Admin:** the account that signs up as `admin@itsm.lab` becomes the admin.
Change this with `set ADMIN_EMAILS=you@example.com` before starting.

Reset all data: stop the app and delete the `instance` folder.

## Demo script (live presentation)
1. Create account `admin@itsm.lab` → open the link in Inbox (demo) → Continue → create a passkey (Windows Hello) → backup codes shown once.
2. Sign out → **Sign in with a passkey**. On the account page the session is new, and the activity log shows `rotated_from=yes`.
3. Admin → invite `bob@itsm.lab`. Open his link in a **private window** and register a passkey there (or use a phone).
4. Admin → **Revoke + reset** Bob → Bob's window is signed out immediately.
5. Sign out → **E-mail me a link** → signed in with `magic_link` → click Admin → asked for the passkey again (step-up).
6. Open the same link again → "already used". Request a link, then open it in another browser → "different browser".
7. **Lost your device?** → backup code login → try the same code again → rejected.
8. **Reset my passkeys** → link + backup code → everything wiped → new passkey.
9. Send 4 link requests for one e-mail → the 4th shows "Too many attempts" (429).

## Tests (security test log)

```powershell
python -m pytest -v tests/test_security.py          # 28 tests, one per defence
python tests/e2e_demo.py --shots screenshots        # full flow in Chromium with a virtual passkey (app must be running)
```
For the e2e script, run `pip install playwright` and `python -m playwright install chromium` first.

## Files
- `app.py`: app factory, security headers, error pages, log redaction
- `auth.py`: sign-up, passkey register and login, magic link, backup codes, reset, step-up, logout
- `account.py`: user page (passkeys, codes, sessions, activity)
- `admin.py`: invite, revoke, disable, group actions
- `security.py`: sessions, CSRF, one-time tokens, backup codes, audit log, access decorators
- `db.py`: SQLite schema. `config.py`: all settings. `dev.py`: demo inbox.
- `static/webauthn.js`: browser side of WebAuthn

## Known limits (honest)
- Runs over http://localhost (browsers treat it as a secure context). A real deployment needs HTTPS (HSTS turns on automatically when `ORIGIN` starts with https).
- The demo inbox replaces SMTP and must be disabled in production (`DEMO_MODE=0`).
- Rate limits are kept in memory and reset on restart. Production would use Redis.
- Magic-link security equals the security of the user's mailbox. This is why that session is low-assurance and reset also needs a backup code.
