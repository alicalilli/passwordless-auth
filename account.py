"""The signed-in user's page: passkeys, backup codes, active sessions, recent activity."""
from flask import Blueprint, abort, g, redirect, render_template, url_for

from db import execute, query
from security import (flash, log_event, login_required, new_backup_codes, remaining_backup_codes,
                      revoke_user_sessions, send_mail, sess_pop, sess_set, step_up_required)

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.get("")
@login_required
def home():
    uid = g.user["id"]
    return render_template(
        "account.html",
        passkeys=query("SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at", (uid,)),
        codes_left=remaining_backup_codes(uid),
        sessions=query("SELECT * FROM sessions WHERE user_id = ? ORDER BY last_seen DESC", (uid,)),
        events=query("SELECT * FROM events WHERE user_id = ? ORDER BY id DESC LIMIT 12", (uid,)),
        current=g.sess["id_hash"],
    )


@bp.post("/passkeys/<int:pk_id>/delete")
@step_up_required()
def delete_passkey(pk_id):
    uid = g.user["id"]
    pk = query("SELECT * FROM passkeys WHERE id = ? AND user_id = ?", (pk_id, uid), one=True)
    if pk is None:
        abort(404)                                   # cannot touch another user's passkey (IDOR check)
    total = query("SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?", (uid,), one=True)["n"]
    if total <= 1:
        flash("You cannot remove your only passkey. Add another one first.", "error")
        return redirect(url_for("account.home"))
    execute("DELETE FROM passkeys WHERE id = ?", (pk_id,))
    log_event("passkey_removed", user_id=uid, email=g.user["email"], detail=f"name={pk['name']}")
    send_mail(g.user["email"], "A passkey was removed", f"The passkey '{pk['name']}' was removed from your account.")
    flash(f"Passkey '{pk['name']}' removed.", "ok")
    return redirect(url_for("account.home"))


@bp.post("/backup-codes")
@step_up_required()
def regenerate_codes():
    sess_set("show_codes", new_backup_codes(g.user["id"]))
    log_event("backup_codes_generated", user_id=g.user["id"], email=g.user["email"], detail="old codes invalidated")
    send_mail(g.user["email"], "New backup codes", "New backup codes were generated. The old ones no longer work.")
    return redirect(url_for("account.show_codes"))


@bp.get("/backup-codes/show")
@login_required
def show_codes():
    codes = sess_pop("show_codes")                   # shown exactly once
    if not codes:
        return redirect(url_for("account.home"))
    return render_template("backup_codes.html", codes=codes)


@bp.post("/sessions/revoke-others")
@login_required
def revoke_others():
    n = revoke_user_sessions(g.user["id"], keep_current=True)
    log_event("sessions_revoked", user_id=g.user["id"], email=g.user["email"], detail=f"others={n}")
    flash(f"Signed out {n} other session(s).", "ok")
    return redirect(url_for("account.home"))
