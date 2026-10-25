// Browser side of WebAuthn: converts the server's JSON options to ArrayBuffers, calls the
// authenticator (Windows Hello, phone, security key) and posts the signed result back.
(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;

  const b64urlToBuf = (s) => {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
  };
  const bufToB64url = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  function showError(msg) {
    const box = document.getElementById('js-msg');
    box.textContent = msg;
    box.classList.remove('hidden');
  }

  async function post(url, body) {
    const r = await fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify(body || {}),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
    return data;
  }

  function credToJSON(cred) {
    const r = cred.response;
    const out = { id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
                  clientExtensionResults: cred.getClientExtensionResults(), response: {} };
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    if (r.attestationObject) {               // registration
      out.response.clientDataJSON = bufToB64url(r.clientDataJSON);
      out.response.attestationObject = bufToB64url(r.attestationObject);
      out.response.transports = r.getTransports ? r.getTransports() : [];
    } else {                                 // authentication
      out.response.clientDataJSON = bufToB64url(r.clientDataJSON);
      out.response.authenticatorData = bufToB64url(r.authenticatorData);
      out.response.signature = bufToB64url(r.signature);
      out.response.userHandle = r.userHandle ? bufToB64url(r.userHandle) : null;
    }
    return out;
  }

  async function register() {
    const opts = await post('/passkey/register/options');
    opts.challenge = b64urlToBuf(opts.challenge);
    opts.user.id = b64urlToBuf(opts.user.id);
    (opts.excludeCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));
    const cred = await navigator.credentials.create({ publicKey: opts });
    const name = (document.getElementById('pk-name') || {}).value || '';
    const res = await post('/passkey/register/verify', { credential: credToJSON(cred), name });
    location.href = res.redirect;
  }

  async function authenticate(optionsUrl, verifyUrl) {
    const opts = await post(optionsUrl);
    opts.challenge = b64urlToBuf(opts.challenge);
    (opts.allowCredentials || []).forEach((c) => (c.id = b64urlToBuf(c.id)));
    const cred = await navigator.credentials.get({ publicKey: opts });
    const res = await post(verifyUrl, { credential: credToJSON(cred) });
    location.href = res.redirect;
  }

  function wire(id, fn) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', async () => {
      if (!window.PublicKeyCredential) return showError('This browser does not support passkeys.');
      el.disabled = true;
      try { await fn(el); }
      catch (e) {
        showError(e.name === 'NotAllowedError' ? 'Cancelled or timed out. Try again.' : e.message);
      } finally { el.disabled = false; }
    });
  }

  wire('passkey-register', register);
  wire('passkey-login', () => authenticate('/passkey/login/options', '/passkey/login/verify'));
  wire('passkey-reauth', (el) => {
    const next = encodeURIComponent(el.dataset.next || '/account');
    return authenticate('/passkey/reauth/options', `/passkey/reauth/verify?next=${next}`);
  });
})();
