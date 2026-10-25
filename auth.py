import json
import re
import secrets

from flask import Blueprint, Response, g, jsonify, redirect, render_template, request, url_for
from webauthn import (base64url_to_bytes, generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response, verify_registration_response)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

import config
from db import execute, now, query
from extensions import email_key, limiter
from security import (check_backup_code, flash, end_session, ensure_session, consume_token, invalidate_tokens,
                      issue_token, link, log_event, login_required, new_backup_codes, recent_strong_auth,
                      remaining_backup_codes, revoke_user_sessions, safe_next, send_mail, sess_get, sess_pop,
                      sess_set, start_authenticated_session)

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[a-z]{2,}$")
GENERIC_LINK_MSG = "If an account exists for that address, a sign-in link is on its way. It works once and expires in 10 minutes."


def clean_email(value):
    email = (value or "").strip().lower()
    return email if EMAIL_RE.match(email) and len(email) <= 254 else None


def user_by_email(email):
    return query("SELECT * FROM users WHERE email = ?", (email,), one=True)


def json_options(options):
    return Response(options_to_json(options), mimetype="application/json")


@bp.get("/")
def index():
    return redirect(url_for("account.home") if g.user else url_for("auth.login"))


@bp.get("/login")
def login():
    if g.user:
        return redirect(url_for("account.home"))
    ensure_session()
    return render_template("login.html")


@bp.route("/signup", methods=["GET", "POST"])
@limiter.limit(config.LIMIT_IP_AUTH, methods=["POST"])
@limiter.limit(config.LIMIT_EMAIL_LINK, methods=["POST"], key_func=email_key)
def signup():
    if request.method == "GET":
        ensure_session()
        return render_template("signup.html")
    email = clean_email(request.form.get("email"))
    name = (request.form.get("name") or "").strip()[:60]
    if not email or not name:
        flash("Enter your name and a valid e-mail address.", "error")
        return render_template("signup.html"), 400
    existing = user_by_email(email)
    token = issue_token("signup", email, config.SIGNUP_LINK_TTL, payload={"name": name})
    if existing:
        send_mail(email, "Someone tried to create an account with your address",
                  "An account already exists for this address. If this was you, sign in with your passkey "
                  f"or ask for a sign-in link at {config.ORIGIN}/login . If not, you can ignore this message.")
    else:
        send_mail(email, "Confirm your e-mail to create your account",
                  f"Hello {name},\nopen this link to confirm your address and register a passkey:\n{link(token)}\n"
                  "The link works once and expires in 30 minutes.")
    log_event("signup_requested", email=email, detail="existing" if existing else "new")
    return render_template("check_email.html",
                           message="We sent a confirmation link to that address. Open it in this browser to continue.")


@bp.post("/auth/magic")
@limiter.limit(config.LIMIT_IP_AUTH)
@limiter.limit(config.LIMIT_EMAIL_LINK, key_func=email_key)
def magic_request():
    email = clean_email(request.form.get("email"))
    if not email:
        flash("Enter a valid e-mail address.", "error")
        return redirect(url_for("auth.login"))
    user = user_by_email(email)
    token = issue_token("login", email, config.MAGIC_LINK_TTL)
    if user and user["status"] == "active":
        send_mail(email, "Your sign-in link",
                  f"Open this link in the same browser to sign in:\n{link(token)}\n"
                  "It works once and expires in 10 minutes. Didn't ask for it? Ignore this e-mail.")
    log_event("magic_link_requested", email=email, detail="known" if user else "unknown")
    return render_template("check_email.html", message=GENERIC_LINK_MSG)


@bp.get("/auth/link")
def link_landing():
    ensure_session()
    return render_template("link_confirm.html", token=request.args.get("t", ""))


@bp.post("/auth/link")
@limiter.limit(config.LIMIT_IP_AUTH)
def link_consume():
    row, reason = consume_token(request.form.get("t", ""))
    if row is None:
        log_event("link_rejected", "failure", detail=reason)
        msg = {"other_browser": "This link was requested from a different browser. Request a new one here.",
               "expired": "This link has expired. Request a new one.",
               "already_used": "This link was already used. Request a new one."}.get(reason, "This link is not valid.")
        flash(msg, "error")
        return redirect(url_for("auth.login"))

    email, purpose = row["email"], row["purpose"]
    user = user_by_email(email)

    if purpose == "signup":
        if user is None:
            name = json.loads(row["payload"] or "{}").get("name", email.split("@")[0])
            role = "admin" if email in config.ADMIN_EMAILS else "user"
            grp = "staff" if role == "admin" else "students"
            execute("INSERT INTO users (email, display_name, user_handle, grp, role, created_at) VALUES (?,?,?,?,?,?)",
                    (email, name, secrets.token_bytes(32), grp, role, now()))
            user = user_by_email(email)
            log_event("signup_completed", user_id=user["id"], email=email, detail=f"role={role}")
        start_authenticated_session(user, "signup_link")
        return redirect(url_for("auth.enroll"))

    if user is None or user["status"] != "active":
        log_event("link_rejected", "failure", email=email, detail="no active account")
        flash("This link is not valid.", "error")
        return redirect(url_for("auth.login"))

    if purpose == "login":
        start_authenticated_session(user, "magic_link")
        log_event("login_success", user_id=user["id"], email=email, detail="method=magic_link")
        send_mail(email, "New sign-in with an e-mail link",
                  "Your account was just signed in with an e-mail link. If this was not you, reset your credentials.")
        return redirect(url_for("account.home"))

    if purpose == "enroll":
        start_authenticated_session(user, "enroll_link")
        log_event("enroll_link_used", user_id=user["id"], email=email)
        return redirect(url_for("auth.enroll"))

    if purpose == "reset":
        sess_set("reset_email", email)
        sess_set("reset_at", now())
        return redirect(url_for("auth.reset_confirm"))

    flash("This link is not valid.", "error")
    return redirect(url_for("auth.login"))


@bp.get("/enroll")
@login_required
def enroll():
    if not recent_strong_auth():
        return redirect(url_for("auth.reauth", next=url_for("auth.enroll")))
    count = query("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?", (g.user["id"],), one=True)["n"]
    return render_template("enroll.html", count=count)


@bp.post("/passkey/register/options")
@limiter.limit(config.LIMIT_PASSKEY)
@login_required
def register_options():
    if not recent_strong_auth():
        return jsonify(error="Please confirm it's you first."), 403
    existing = query("SELECT credential_id FROM passkeys WHERE user_id = ?", (g.user["id"],))
    options = generate_registration_options(
        rp_id=config.RP_ID, rp_name=config.RP_NAME,
        user_id=g.user["user_handle"], user_name=g.user["email"], user_display_name=g.user["display_name"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=r["credential_id"]) for r in existing],
    )
    sess_set("reg_challenge", bytes_to_base64url(options.challenge))
    return json_options(options)


@bp.post("/passkey/register/verify")
@limiter.limit(config.LIMIT_PASSKEY)
@login_required
def register_verify():
    challenge = sess_pop("reg_challenge")
    body = request.get_json(silent=True) or {}
    if not challenge or not recent_strong_auth():
        return jsonify(error="Registration expired, try again."), 400
    try:
        v = verify_registration_response(credential=body.get("credential"),
                                         expected_challenge=base64url_to_bytes(challenge),
                                         expected_rp_id=config.RP_ID, expected_origin=config.ORIGIN,
                                         require_user_verification=True)
    except Exception as exc:
        log_event("passkey_register", "failure", user_id=g.user["id"], email=g.user["email"], detail=str(exc)[:200])
        return jsonify(error="The passkey could not be verified."), 400
    transports = ",".join((body.get("credential") or {}).get("response", {}).get("transports", []) or [])
    n = query("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?", (g.user["id"],), one=True)["n"]
    name = (body.get("name") or "").strip()[:40] or f"Passkey {n + 1}"
    execute("INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, transports, backed_up, name, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (g.user["id"], v.credential_id, v.credential_public_key, v.sign_count, transports,
             1 if v.credential_backed_up else 0, name, now()))
    log_event("passkey_registered", user_id=g.user["id"], email=g.user["email"],
              detail=f"name={name} synced={v.credential_backed_up}")
    send_mail(g.user["email"], "A new passkey was added",
              f"The passkey '{name}' was added to your account. If this was not you, reset your credentials now.")
    nxt = url_for("account.home")
    if remaining_backup_codes(g.user["id"]) == 0:
        sess_set("show_codes", new_backup_codes(g.user["id"]))
        log_event("backup_codes_generated", user_id=g.user["id"], email=g.user["email"])
        nxt = url_for("account.show_codes")
    sess_pop("need_enroll")
    return jsonify(ok=True, redirect=nxt)


def _assertion_options(user=None):
    allow = None
    if user is not None:
        allow = [PublicKeyCredentialDescriptor(id=r["credential_id"])
                 for r in query("SELECT credential_id FROM passkeys WHERE user_id = ?", (user["id"],))]
    options = generate_authentication_options(rp_id=config.RP_ID, allow_credentials=allow,
                                              user_verification=UserVerificationRequirement.REQUIRED)
    sess_set("auth_challenge", bytes_to_base64url(options.challenge))
    return options


def _verify_assertion(body, expected_user=None):
    challenge = sess_pop("auth_challenge")
    cred = body.get("credential") or {}
    if not challenge or not cred.get("rawId"):
        return None, "no challenge"
    try:
        cred_id = base64url_to_bytes(cred["rawId"])
    except Exception:
        return None, "bad id"
    pk = query("SELECT * FROM passkeys WHERE credential_id = ?", (cred_id,), one=True)
    if pk is None:
        return None, "unknown credential"
    user = query("SELECT * FROM users WHERE id = ?", (pk["user_id"],), one=True)
    if user is None or user["status"] != "active":
        return None, "account disabled"
    if expected_user is not None and user["id"] != expected_user["id"]:
        return None, "credential of another user"
    handle = (cred.get("response") or {}).get("userHandle")
    if handle and base64url_to_bytes(handle) != user["user_handle"]:
        return None, "user handle mismatch"
    try:
        v = verify_authentication_response(credential=cred, expected_challenge=base64url_to_bytes(challenge),
                                           expected_rp_id=config.RP_ID, expected_origin=config.ORIGIN,
                                           credential_public_key=pk["public_key"],
                                           credential_current_sign_count=pk["sign_count"],
                                           require_user_verification=True)
    except Exception as exc:
        return None, f"verify failed: {str(exc)[:150]}"
    execute("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?", (v.new_sign_count, now(), pk["id"]))
    return user, pk["name"]


@bp.post("/passkey/login/options")
@limiter.limit(config.LIMIT_PASSKEY)
def login_options():
    return json_options(_assertion_options())


@bp.post("/passkey/login/verify")
@limiter.limit(config.LIMIT_PASSKEY)
def login_verify():
    user, info = _verify_assertion(request.get_json(silent=True) or {})
    if user is None:
        log_event("login_failure", "failure", detail=f"method=passkey reason={info}")
        return jsonify(error="That passkey was not accepted."), 400
    start_authenticated_session(user, "passkey")
    log_event("login_success", user_id=user["id"], email=user["email"], detail=f"method=passkey key={info}")
    nxt = safe_next(request.args.get("next")) or url_for("account.home")
    return jsonify(ok=True, redirect=nxt)


@bp.get("/reauth")
@login_required
def reauth():
    has_pk = query("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?", (g.user["id"],), one=True)["n"] > 0
    return render_template("reauth.html", next=safe_next(request.args.get("next")) or url_for("account.home"),
                           passkey_only=request.args.get("pk") == "1", has_passkey=has_pk)


@bp.post("/passkey/reauth/options")
@limiter.limit(config.LIMIT_PASSKEY)
@login_required
def reauth_options():
    return json_options(_assertion_options(g.user))


@bp.post("/passkey/reauth/verify")
@limiter.limit(config.LIMIT_PASSKEY)
@login_required
def reauth_verify():
    me = g.user
    user, info = _verify_assertion(request.get_json(silent=True) or {}, expected_user=me)
    if user is None:
        log_event("step_up", "failure", user_id=me["id"], email=me["email"], detail=info)
        return jsonify(error="That passkey was not accepted."), 400
    start_authenticated_session(user, "passkey")
    log_event("step_up", user_id=user["id"], email=user["email"], detail="method=passkey")
    return jsonify(ok=True, redirect=safe_next(request.args.get("next")) or url_for("account.home"))


@bp.post("/reauth/backup")
@limiter.limit(config.LIMIT_IP_AUTH)
@login_required
def reauth_backup():
    me = g.user
    nxt = safe_next(request.form.get("next")) or url_for("account.home")
    if not check_backup_code(me, request.form.get("code")):
        log_event("step_up", "failure", user_id=me["id"], email=me["email"], detail="method=backup_code")
        flash("That code is not valid.", "error")
        return redirect(url_for("auth.reauth", next=nxt))
    start_authenticated_session(me, "backup_code")
    log_event("step_up", user_id=me["id"], email=me["email"], detail="method=backup_code")
    _warn_codes_left(me)
    return redirect(nxt)


def _warn_codes_left(user):
    left = remaining_backup_codes(user["id"])
    send_mail(user["email"], "A backup code was used",
              f"A backup code was used on your account. {left} codes are left. If this was not you, reset your credentials.")
    if left <= 3:
        flash(f"Only {left} backup codes left. Generate new ones on your account page.", "warn")


@bp.route("/recover", methods=["GET", "POST"])
@limiter.limit(config.LIMIT_IP_AUTH, methods=["POST"])
@limiter.limit(config.LIMIT_EMAIL_BACKUP, methods=["POST"], key_func=email_key)
def recover():
    if request.method == "GET":
        ensure_session()
        return render_template("recover.html")
    email = clean_email(request.form.get("email"))
    user = user_by_email(email) if email else None
    ok = check_backup_code(user if user and user["status"] == "active" else None, request.form.get("code"))
    if not ok:
        log_event("login_failure", "failure", user_id=user["id"] if user else None, email=email,
                  detail="method=backup_code")
        flash("Invalid e-mail or backup code.", "error")
        return render_template("recover.html"), 401
    start_authenticated_session(user, "backup_code")
    log_event("login_success", user_id=user["id"], email=email, detail="method=backup_code")
    _warn_codes_left(user)
    flash("Signed in with a backup code. Add a new passkey now if you lost your device.", "warn")
    return redirect(url_for("account.home"))


@bp.route("/reset", methods=["GET", "POST"])
@limiter.limit(config.LIMIT_IP_AUTH, methods=["POST"])
@limiter.limit(config.LIMIT_EMAIL_LINK, methods=["POST"], key_func=email_key)
def reset_request():
    if request.method == "GET":
        ensure_session()
        return render_template("reset.html")
    email = clean_email(request.form.get("email"))
    if not email:
        flash("Enter a valid e-mail address.", "error")
        return render_template("reset.html"), 400
    user = user_by_email(email)
    token = issue_token("reset", email, config.RESET_LINK_TTL)
    if user and user["status"] == "active":
        send_mail(email, "Reset your sign-in credentials",
                  f"Open this link in the same browser to reset your passkeys:\n{link(token)}\n"
                  "You will also need one of your backup codes. The link expires in 15 minutes.")
    log_event("reset_requested", email=email, detail="known" if user else "unknown")
    return render_template("check_email.html",
                           message="If an account exists for that address, a reset link is on its way.")


@bp.route("/reset/confirm", methods=["GET", "POST"])
@limiter.limit(config.LIMIT_IP_AUTH, methods=["POST"])
def reset_confirm():
    email, started = sess_get("reset_email"), sess_get("reset_at", 0)
    if not email or now() - started > config.RESET_LINK_TTL:
        flash("Start the reset again.", "error")
        return redirect(url_for("auth.reset_request"))
    user = user_by_email(email)
    if request.method == "GET":
        return render_template("reset_confirm.html", email=email)
    if not check_backup_code(user, request.form.get("code")):
        log_event("reset_completed", "failure", user_id=user["id"], email=email, detail="bad backup code")
        flash("That backup code is not valid. No codes left? Ask an administrator to reset your account.", "error")
        return render_template("reset_confirm.html", email=email), 401
    sess_pop("reset_email"); sess_pop("reset_at")
    execute("DELETE FROM passkeys WHERE user_id = ?", (user["id"],))
    execute("DELETE FROM backup_codes WHERE user_id = ?", (user["id"],))
    killed = revoke_user_sessions(user["id"])
    invalidate_tokens(email)
    start_authenticated_session(user, "reset")
    log_event("reset_completed", user_id=user["id"], email=email, detail=f"sessions_revoked={killed}")
    send_mail(email, "Your credentials were reset",
              "All passkeys and backup codes on your account were removed and every device was signed out. "
              "If this was not you, contact the administrator immediately.")
    return redirect(url_for("auth.enroll"))


@bp.post("/logout")
def logout():
    if g.user:
        log_event("logout", user_id=g.user["id"], email=g.user["email"])
    end_session()
    flash("You are signed out.", "ok")
    return redirect(url_for("auth.login"))
