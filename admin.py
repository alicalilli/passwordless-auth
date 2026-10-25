import secrets

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

import config
from auth import clean_email, user_by_email
from db import execute, now, query
from security import (admin_required, flash, invalidate_tokens, issue_token, link, log_event,
                      revoke_user_sessions, send_mail)

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _target(user_id):
    u = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if u is None:
        abort(404)
    if u["id"] == g.user["id"]:
        flash("Use your own account page for your account; admins cannot lock themselves out here.", "error")
        return None
    return u


def _send_enroll_link(u, reason):
    token = issue_token("enroll", u["email"], config.ENROLL_LINK_TTL, bind=False)
    send_mail(u["email"], "Set up your passkey",
              f"{reason}\nOpen this link to register a new passkey:\n{link(token)}\n"
              "It works once and expires in 24 hours.")


def _revoke_credentials(u):
    pk = execute("DELETE FROM passkeys WHERE user_id = ?", (u["id"],)).rowcount
    execute("DELETE FROM backup_codes WHERE user_id = ?", (u["id"],))
    sess = revoke_user_sessions(u["id"])
    invalidate_tokens(u["email"])
    _send_enroll_link(u, "An administrator reset the sign-in credentials on your account.")
    return pk, sess


@bp.get("")
@admin_required
def home():
    users = query("""
        SELECT u.*,
          (SELECT COUNT(*) FROM passkeys p WHERE p.user_id = u.id) AS passkeys,
          (SELECT COUNT(*) FROM backup_codes b WHERE b.user_id = u.id AND b.used_at IS NULL) AS codes,
          (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) AS sessions,
          (SELECT MAX(ts) FROM events e WHERE e.user_id = u.id AND e.event = 'login_success') AS last_login
        FROM users u ORDER BY u.grp, u.email""")
    events = query("SELECT * FROM events ORDER BY id DESC LIMIT 40")
    return render_template("admin.html", users=users, events=events, groups=config.GROUPS)


@bp.post("/invite")
@admin_required
def invite():
    email = clean_email(request.form.get("email"))
    name = (request.form.get("name") or "").strip()[:60]
    grp = request.form.get("group")
    if not email or not name or grp not in config.GROUPS:
        flash("Enter a name, a valid e-mail and a group.", "error")
        return redirect(url_for("admin.home"))
    if user_by_email(email):
        flash("That user already exists.", "error")
        return redirect(url_for("admin.home"))
    execute("INSERT INTO users (email, display_name, user_handle, grp, created_at) VALUES (?,?,?,?,?)",
            (email, name, secrets.token_bytes(32), grp, now()))
    u = user_by_email(email)
    _send_enroll_link(u, f"Hello {name}, an administrator created an account for you.")
    log_event("admin_invite", user_id=g.user["id"], email=g.user["email"], detail=f"target={email} group={grp}")
    flash(f"Invited {email}. The enrolment link is in their inbox.", "ok")
    return redirect(url_for("admin.home"))


@bp.post("/user/<int:user_id>/<action>")
@admin_required
def user_action(user_id, action):
    u = _target(user_id)
    if u is None:
        return redirect(url_for("admin.home"))
    if action == "signout":
        n = revoke_user_sessions(u["id"])
        detail = f"sessions={n}"
        flash(f"{u['email']}: {n} session(s) ended.", "ok")
    elif action == "revoke":
        pk, sess = _revoke_credentials(u)
        detail = f"passkeys={pk} sessions={sess}"
        flash(f"{u['email']}: credentials revoked, enrolment link sent.", "ok")
    elif action in ("disable", "enable"):
        execute("UPDATE users SET status = ? WHERE id = ?", ("disabled" if action == "disable" else "active", u["id"]))
        if action == "disable":
            revoke_user_sessions(u["id"])
            invalidate_tokens(u["email"])
        detail = action
        flash(f"{u['email']}: account {action}d.", "ok")
    elif action == "group":
        grp = request.form.get("group")
        if grp not in config.GROUPS:
            abort(400)
        execute("UPDATE users SET grp = ? WHERE id = ?", (grp, u["id"]))
        detail = f"group={grp}"
        flash(f"{u['email']} moved to {grp}.", "ok")
    else:
        abort(404)
    log_event(f"admin_{action}", user_id=g.user["id"], email=g.user["email"], detail=f"target={u['email']} {detail}")
    return redirect(url_for("admin.home"))


@bp.post("/group/<grp>/<action>")
@admin_required
def group_action(grp, action):
    if grp not in config.GROUPS or action not in ("signout", "revoke"):
        abort(404)
    if request.form.get("confirm") != grp:
        flash(f"Type the group name '{grp}' to confirm.", "error")
        return redirect(url_for("admin.home"))
    members = query("SELECT * FROM users WHERE grp = ? AND id != ?", (grp, g.user["id"]))
    for u in members:
        if action == "signout":
            revoke_user_sessions(u["id"])
        else:
            _revoke_credentials(u)
    log_event(f"admin_group_{action}", user_id=g.user["id"], email=g.user["email"],
              detail=f"group={grp} users={len(members)}")
    flash(f"Group '{grp}': {action} applied to {len(members)} user(s).", "ok")
    return redirect(url_for("admin.home"))
