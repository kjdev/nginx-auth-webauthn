/*
 * Development-only WebAuthn registration client.
 *
 * Flow: POST /register/begin -> navigator.credentials.create() ->
 * POST /register/complete. The Python server (register.py) verifies the
 * attestation and writes the credential to Redis. Reference implementation;
 * production registration should use tools/admin/auth-webauthn-admin.
 */
'use strict';

(function () {
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

  /* Decode the server JSON into PublicKeyCredentialCreationOptions. */
  function toCreationOptions(json) {
    return {
      rp: json.rp,
      user: {
        id: b64urlToBuf(json.user.id),
        name: json.user.name,
        displayName: json.user.displayName,
      },
      challenge: b64urlToBuf(json.challenge),
      pubKeyCredParams: json.pubKeyCredParams,
      /*
       * timeout is an unsigned long in WebIDL: a null/0 value becomes "no
       * timeout" and create() waits forever. Fall back to a finite default.
       */
      timeout: json.timeout || 120000,
      excludeCredentials: (json.excludeCredentials || []).map((c) => ({
        type: c.type,
        id: b64urlToBuf(c.id),
      })),
      authenticatorSelection: json.authenticatorSelection,
      attestation: json.attestation,
    };
  }

  /* Shape the new credential into the JSON register.py expects. */
  function toCompleteBody(credential) {
    const r = credential.response;
    return {
      id: credential.id,
      rawId: bufToB64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        attestationObject: bufToB64url(r.attestationObject),
      },
    };
  }

  async function register() {
    if (!window.PublicKeyCredential) {
      setStatus('This browser does not support WebAuthn.', 'err');
      return;
    }
    const userId = document.getElementById('user-id').value.trim();
    if (!userId) {
      setStatus('Please enter a user ID.', 'err');
      return;
    }

    setStatus('Starting registration...');
    try {
      const beginResp = await fetch('/register/begin', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId }),
      });
      if (!beginResp.ok) {
        const e = await beginResp.json().catch(() => ({}));
        throw new Error(e.error || `begin HTTP ${beginResp.status}`);
      }
      const publicKey = toCreationOptions(await beginResp.json());

      setStatus('Waiting for the authenticator...');
      const credential = await navigator.credentials.create({ publicKey });

      setStatus('Verifying and storing on the server...');
      const completeResp = await fetch('/register/complete', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(toCompleteBody(credential)),
      });

      const result = await completeResp.json().catch(() => ({}));
      if (completeResp.ok && result.ok) {
        setStatus(`Registration succeeded: cid=${result.credential_id}`, 'ok');
      } else {
        setStatus(`Registration failed: ${result.error || completeResp.status}`,
                  'err');
      }
    } catch (err) {
      if (err && err.name === 'NotAllowedError') {
        setStatus('The operation was cancelled.', 'err');
      } else {
        setStatus(`Error: ${err && err.message ? err.message : err}`, 'err');
      }
    }
  }

  document.getElementById('register').addEventListener('click', register);
})();
