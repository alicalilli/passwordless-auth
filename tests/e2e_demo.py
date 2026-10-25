"""End-to-end run of every flow in a real Chromium with a virtual passkey authenticator.

Start the app first (python app.py), then:  python tests/e2e_demo.py [--shots DIR]
Needs: pip install playwright && python -m playwright install chromium
"""
import os
import re
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE", "http://localhost:5000")
SHOTS = sys.argv[sys.argv.index("--shots") + 1] if "--shots" in sys.argv else None
LINK = re.compile(r'href="(http://[^"]+/auth/link\?t=[^"]+)"')
n = 0


def shot(page, name):
    global n
    if SHOTS:
        n += 1
        os.makedirs(SHOTS, exist_ok=True)
        page.screenshot(path=os.path.join(SHOTS, f"{n:02d}_{name}.png"), full_page=True)


def step(msg):
    print(f"  [ok] {msg}")


def add_authenticator(context, page):
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
    return cdp


def latest_link(page, to):
    html = page.request.get(f"{BASE}/dev/outbox").text()
    for block in html.split('<article class="card mail">')[1:]:
        if f"to {to}" in block:
            m = LINK.search(block)
            if m:
                return m.group(1).replace("&amp;", "&")
    raise AssertionError(f"no link for {to}")


def sid(context):
    return next((c["value"] for c in context.cookies() if c["name"] == "__Host-sid"), None)


def open_link(page, url):
    page.goto(url)
    with page.expect_navigation():
        page.click("button:has-text('Continue')")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless="--headed" not in sys.argv)
        # ---------------- admin signs up and registers a passkey
        ctx = browser.new_context(viewport={"width": 1200, "height": 850})
        page = ctx.new_page()
        add_authenticator(ctx, page)
        page.goto(f"{BASE}/signup")
        page.fill("#name", "Ali Admin"); page.fill("#email", "admin@itsm.lab")
        shot(page, "signup")
        page.click("text=Send confirmation link")
        assert "Check your inbox" in page.content()
        shot(page, "check_inbox")
        page.goto(f"{BASE}/dev/outbox"); shot(page, "outbox_signup")
        open_link(page, latest_link(page, "admin@itsm.lab"))
        assert "/enroll" in page.url
        page.fill("#pk-name", "Laptop Windows Hello"); shot(page, "enroll")
        page.click("#passkey-register"); page.wait_for_url("**/backup-codes/show")
        codes = page.locator("#codes code").all_inner_texts()
        assert len(codes) == 10
        shot(page, "backup_codes")
        step(f"sign-up + passkey registered, {len(codes)} backup codes")
        page.click("text=I saved them"); shot(page, "account")

        # ---------------- logout, passkey login, session rotation
        page.click("text=Sign out"); before = sid(ctx)
        page.goto(f"{BASE}/login"); shot(page, "login")
        pre = sid(ctx)
        page.click("#passkey-login"); page.wait_for_url("**/account")
        post = sid(ctx)
        assert pre and post and pre != post
        step(f"passkey login works, session ID rotated {pre[:8]}... -> {post[:8]}...")

        # old cookie no longer valid
        replay = p.request.new_context()            # separate client, like an attacker with the old cookie
        r = replay.get(f"{BASE}/account", headers={"Cookie": f"__Host-sid={pre}"}, max_redirects=0)
        assert r.status == 302 and "/login" in r.headers["location"]
        step("pre-login session cookie rejected after login (302 to /login)")

        # ---------------- admin area (fresh passkey) + invite bob
        page.goto(f"{BASE}/admin"); assert "Administration" in page.content()
        page.fill("form[action='/admin/invite'] input[name=name]", "Bob Student")
        page.fill("form[action='/admin/invite'] input[name=email]", "bob@itsm.lab")
        page.click("text=Create and send enrolment link")
        page.goto(f"{BASE}/admin")
        shot(page, "admin")
        step("admin invited bob")

        bctx = browser.new_context(viewport={"width": 1200, "height": 850})
        bob = bctx.new_page(); add_authenticator(bctx, bob)
        open_link(bob, latest_link(page, "bob@itsm.lab"))
        bob.click("#passkey-register"); bob.wait_for_url("**/backup-codes/show")
        bob_codes = bob.locator("#codes code").all_inner_texts()
        bob.click("text=I saved them")
        step("bob enrolled through admin enrolment link (works in another browser)")

        # bob is not admin
        bob.goto(f"{BASE}/admin")
        assert "/reauth" in bob.url                 # step-up is asked first, the role check comes after
        with bob.expect_navigation():
            bob.click("#passkey-reauth")
        assert "403" in bob.content()
        shot(bob, "bob_403")
        step("bob (role user) gets 403 on /admin even after passkey step-up")

        # ---------------- central revocation
        page.goto(f"{BASE}/admin")
        row = page.locator("tr", has_text="bob@itsm.lab")
        row.locator("text=Revoke + reset").click()
        bob.goto(f"{BASE}/account"); assert "/login" in bob.url
        step("admin revoked bob: bob's live session is dead, enrolment link re-sent")
        shot(page, "admin_after_revoke")

        # group revoke needs typed confirmation
        page.locator("form.group-row", has_text="students").locator("text=Sign out all").click()
        assert "to confirm" in page.content()
        step("group action refused without typed confirmation")

        # ---------------- magic link login = low assurance
        page.click("text=Sign out")
        page.goto(f"{BASE}/login")
        page.fill("#email", "admin@itsm.lab"); page.click("text=Send link")
        open_link(page, latest_link(page, "admin@itsm.lab"))
        assert "/account" in page.url and "magic_link" in page.content()
        step("magic link login works")
        page.goto(f"{BASE}/admin"); assert "/reauth" in page.url
        shot(page, "reauth_required")
        step("magic-link session must step up with a passkey before /admin")

        # link is single-use
        used = latest_link(page, "admin@itsm.lab")
        page.click("text=Sign out")
        open_link(page, used); assert "already used" in page.content() or "not valid" in page.content()
        step("magic link cannot be reused")

        # link bound to the requesting browser
        page.goto(f"{BASE}/login"); page.fill("#email", "admin@itsm.lab"); page.click("text=Send link")
        other = browser.new_context().new_page()
        open_link(other, latest_link(page, "admin@itsm.lab"))
        assert "different browser" in other.content()
        step("magic link refused in another browser (binding)")

        # ---------------- backup code login
        page.goto(f"{BASE}/recover")
        page.fill("#email", "admin@itsm.lab"); page.fill("#code", codes[0]); page.click("main button.primary")
        assert "/account" in page.url
        step("backup code login works")
        page.click("text=Sign out")
        page.goto(f"{BASE}/recover")
        page.fill("#email", "admin@itsm.lab"); page.fill("#code", codes[0]); page.click("main button.primary")
        assert "Invalid e-mail or backup code" in page.content()
        step("used backup code is rejected")

        # ---------------- self-service reset: link + backup code
        page.goto(f"{BASE}/reset"); page.fill("#email", "admin@itsm.lab"); page.click("text=Send reset link")
        open_link(page, latest_link(page, "admin@itsm.lab"))
        assert "Confirm the reset" in page.content(); shot(page, "reset_confirm")
        page.fill("#code", codes[1]); page.click("text=Reset everything")
        assert "/enroll" in page.url
        page.click("#passkey-register"); page.wait_for_url("**/backup-codes/show")
        step("reset: old passkeys/codes/sessions wiped, new passkey + new codes")
        page.click("text=I saved them")
        shot(page, "account_after_reset")

        browser.close()
    print("\nALL END-TO-END CHECKS PASSED")


if __name__ == "__main__":
    main()
