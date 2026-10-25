# Passwordless Auth

A small Flask web app that signs users in without passwords.

- **Passkeys (WebAuthn):** the main way to sign in, using Windows Hello, Touch ID, a phone or a security key
- **Email sign-in links:** a fallback, single use, valid for 10 minutes and tied to the browser that asked for them
- **Backup codes:** 10 one-time codes for when the passkey device is lost
- **Credential reset:** needs an email link and a backup code; removes all old passkeys and sessions
- **Admin panel:** invite users, sign out, reset or disable a single user or a whole group

The server stores only public keys and hashes (Argon2id for backup codes, SHA-256 for link tokens and session IDs).

## Security features

- Server-side sessions, rotated at every login, with idle and absolute timeouts
- `__Host-` cookies with `Secure`, `HttpOnly` and `SameSite=Lax`
- CSRF tokens and an Origin check on every POST
- Rate limiting per IP and per account
- The same response for existing and non-existing accounts (no user enumeration)
- Re-authentication required for credential changes and the admin panel
- Security headers (CSP, X-Frame-Options, Referrer-Policy and others)
- Email notifications for new sign-ins, new passkeys, backup code use and resets
- An audit log of all authentication events (`instance/auth.log`, JSON lines)

## Running

```
pip install -r requirements.txt
python app.py
```

At startup the app asks for the Gmail app password of the sending account
(create one at https://myaccount.google.com/apppasswords). The password is not stored anywhere.

Open http://localhost:5000 in Chrome or Edge. Use `localhost`, not `127.0.0.1`, because passkeys are bound to the domain.

Settings can be changed with environment variables: `SMTP_USER`, `SMTP_PASSWORD`, `ADMIN_EMAILS`, `PORT`, `ORIGIN`, `RP_ID`.
An account that signs up with an address in `ADMIN_EMAILS` becomes an admin.

To reset all data, delete the `instance` folder.

## Tests

```
python -m pytest -v
```

## Notes

- Over the internet the app must run on HTTPS (set `ORIGIN` and `RP_ID` to the real domain).
- Rate-limit counters are kept in memory and reset when the app restarts.
- An email sign-in link is only as safe as the mailbox it is sent to. That is why it gives limited access
  and a reset also needs a backup code.
