# Login page example (`examples/login/`)

A minimal frontend reference implementation for driving the
`nginx-auth-webauthn` authentication flow (assertion verification) from a
browser.

```
login/
├── index.html   login UI (user ID input + button + status)
└── login.js     /webauthn/challenge → navigator.credentials.get() → /webauthn/verify
```

## How it works

1. `GET /webauthn/challenge` fetches a challenge (32 bytes, base64url) and the
   RP ID.
2. `navigator.credentials.get()` asks the authenticator to sign.
3. The resulting assertion is sent to `POST /webauthn/verify`.
4. On success the module returns a session JWT via `Set-Cookie` and `login.js`
   navigates to `webauthn-success-url` (default `/`). From then on, protected
   locations are reachable with that cookie.

The target user's credential must already be registered in Redis beforehand
(`tools/admin/auth-webauthn-admin register` or `examples/register/`).

## Endpoint and redirect configuration

These can be changed via the `<meta>` tags in `index.html`. The defaults are
same-origin paths:

```html
<meta name="webauthn-challenge-url" content="/webauthn/challenge">
<meta name="webauthn-verify-url" content="/webauthn/verify">
<meta name="webauthn-success-url" content="/">
```

Because the session cookie is sent same-origin, placing the login page, the
endpoints and the protected target on the **same origin** is the simplest
setup.

## nginx.conf example

```nginx
http {
    # shared memory for challenges (required in the http context)
    auth_webauthn_challenge_zone webauthn_challenge:10m;

    # RP / origin (required for WebAuthn verification)
    auth_webauthn_rp_id      example.com;
    auth_webauthn_origin     https://example.com;

    # Redis (where registered credentials are looked up)
    auth_webauthn_redis      127.0.0.1:6379;

    # session JWT signing key (32+ random bytes for HS256)
    auth_webauthn_jwt_secret_file /etc/nginx/webauthn/jwt.key;

    server {
        listen 443 ssl;
        server_name example.com;
        # ssl_certificate / ssl_certificate_key ...

        # login page (static)
        location /login/ {
            alias /path/to/examples/login/;
            index index.html;
        }

        # challenge issuance endpoint
        location = /webauthn/challenge {
            auth_webauthn_challenge_handler on;
        }

        # assertion verification endpoint (Set-Cookie on success)
        location = /webauthn/verify {
            auth_webauthn_verify_handler on;
        }

        # protected target
        location / {
            auth_webauthn on;
            auth_webauthn_signin_url /login/;   # unauthenticated -> 302 to /login/
            # proxy_pass http://backend; etc.
        }
    }
}
```

## Notes

- **HTTPS is required**. WebAuthn only works in a secure context (the exception
  is `localhost`). For local testing you can run it at
  `http://localhost:PORT/login/` (in that case also set
  `auth_webauthn_origin http://localhost:PORT;` and
  `auth_webauthn_jwt_cookie_secure off;`).
- If `auth_webauthn_origin` does not exactly match the actual URL origin, the
  clientDataJSON origin check fails with a 401.
- `allowCredentials` is currently returned as an empty array, so a discoverable
  credential (resident key) is assumed.

## See also

- [`examples/register/`](../register/README.md) — registration page example
- [`docs/DIRECTIVES.md`](../../docs/DIRECTIVES.md) — directive reference
