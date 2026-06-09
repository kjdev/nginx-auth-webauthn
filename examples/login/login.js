/*
 * Minimal WebAuthn authentication client for nginx-auth-webauthn.
 *
 * Flow: GET /webauthn/challenge -> navigator.credentials.get() ->
 * POST /webauthn/verify. On success the server sets a session JWT cookie and
 * this script navigates to the success URL. This is a reference implementation
 * meant to be read; production sites will fold it into their own login page.
 */
'use strict';

(function () {
  const meta = (name, fallback) => {
    const el = document.querySelector(`meta[name="${name}"]`);
    return (el && el.content) || fallback;
  };

  const CHALLENGE_URL = meta('webauthn-challenge-url', '/webauthn/challenge');
  const VERIFY_URL = meta('webauthn-verify-url', '/webauthn/verify');
  const SUCCESS_URL = meta('webauthn-success-url', '/');

  /* base64url (no padding) <-> ArrayBuffer helpers. */
  function b64urlToBuf(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      buf[i] = bin.charCodeAt(i);
    }
    return buf.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  const statusEl = document.getElementById('status');
  function setStatus(msg, kind) {
    statusEl.textContent = msg;
    statusEl.className = kind || '';
  }

  /* Map the /webauthn/challenge JSON into PublicKeyCredentialRequestOptions. */
  function toRequestOptions(json) {
    return {
      challenge: b64urlToBuf(json.challenge),
      rpId: json.rpId,
      /* A null/0 timeout means "no timeout"; fall back to a finite default. */
      timeout: json.timeout || 120000,
      userVerification: json.userVerification || 'preferred',
      /*
       * An empty allowCredentials relies on discoverable credentials
       * (resident keys); the authenticator resolves the user itself.
       */
      allowCredentials: (json.allowCredentials || []).map((c) => ({
        type: c.type || 'public-key',
        id: b64urlToBuf(c.id),
        transports: c.transports,
      })),
    };
  }

  /* Shape the assertion into the body /webauthn/verify expects. */
  function toVerifyBody(credential) {
    const r = credential.response;
    return {
      id: credential.id,
      type: credential.type,
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        authenticatorData: bufToB64url(r.authenticatorData),
        signature: bufToB64url(r.signature),
      },
    };
  }

  async function login() {
    if (!window.PublicKeyCredential) {
      setStatus('This browser does not support WebAuthn.', 'err');
      return;
    }

    setStatus('Fetching a challenge...');
    try {
      /*
       * A user_id is optional: when supplied the server returns that user's
       * allowCredentials, which lets non-discoverable authenticators be
       * selected. Without it the flow relies on discoverable credentials.
       */
      const userIdEl = document.getElementById('user-id');
      const userId = userIdEl && userIdEl.value.trim();
      let challengeUrl = CHALLENGE_URL;
      if (userId) {
        challengeUrl +=
          (CHALLENGE_URL.indexOf('?') === -1 ? '?' : '&') +
          'user_id=' + encodeURIComponent(userId);
      }

      const chResp = await fetch(challengeUrl, {
        credentials: 'same-origin',
      });
      if (!chResp.ok) {
        throw new Error(`challenge HTTP ${chResp.status}`);
      }
      const publicKey = toRequestOptions(await chResp.json());

      setStatus('Waiting for the authenticator...');
      const credential = await navigator.credentials.get({ publicKey });

      setStatus('Verifying on the server...');
      const verifyResp = await fetch(VERIFY_URL, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(toVerifyBody(credential)),
      });

      const result = await verifyResp.json().catch(() => ({}));
      if (verifyResp.ok && result.ok) {
        setStatus('Login succeeded. Redirecting...', 'ok');
        window.location.assign(SUCCESS_URL);
      } else {
        setStatus('Login failed.', 'err');
      }
    } catch (err) {
      if (err && err.name === 'NotAllowedError') {
        setStatus('The operation was cancelled.', 'err');
      } else {
        setStatus(`Error: ${err && err.message ? err.message : err}`, 'err');
      }
    }
  }

  document.getElementById('login').addEventListener('click', login);
})();
