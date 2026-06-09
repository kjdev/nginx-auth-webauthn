# Configuration Examples

This document summarizes typical configuration patterns of `nginx-auth-webauthn` and the wire formats between the client and NGINX. See [DIRECTIVES.md](DIRECTIVES.md) for the details of each directive.

## Prerequisites

- WebAuthn presupposes a secure context (HTTPS). Except for `localhost`, it does not work over HTTP
- Make `auth_webauthn_rp_id` match the origin's domain (or a registrable suffix)
- Specify `auth_webauthn_origin` by exact match including scheme, host, and port
- Credential registration is done with the bundled CLI [auth-webauthn-admin](ADMIN_TOOL.md)

## Pattern 1: Protecting an admin screen (redirect type)

A typical browser-oriented configuration that 302-redirects unauthenticated access to the login page.

```nginx
http {
    auth_webauthn_rp_id           example.com;
    auth_webauthn_origin          https://example.com;
    auth_webauthn_redis           127.0.0.1:6379;
    auth_webauthn_jwt_secret_file /etc/nginx/webauthn_jwt.key;
    auth_webauthn_jwt_alg         HS256;

    server {
        listen 443 ssl;
        server_name example.com;

        # Challenge issuance / Assertion verification endpoints
        location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
        location = /webauthn/verify    { auth_webauthn_verify_handler    on; }

        # Login page (static HTML + JS, place examples/login/ here)
        location = /login {
            root /var/www/webauthn-login;
            try_files /index.html =404;
        }

        # Protected target
        location /admin/ {
            auth_webauthn            on;
            auth_webauthn_signin_url /login;
            auth_webauthn_set_header X-WebAuthn-User $webauthn_user_id;
            proxy_pass               http://backend_admin;
        }
    }
}
```

Accessing `/admin/` while unauthenticated redirects to `/login`; after a successful login a session cookie is issued, and on revisit the request passes through.

## Pattern 2: API gate (401 type)

Omitting `auth_webauthn_signin_url` makes it return 401 without redirecting when unauthenticated. Suited to protecting XHR / fetch-based APIs.

```nginx
location /api/ {
    auth_webauthn on;
    # no signin_url → unauthenticated is 401
    proxy_pass http://backend_api;
}
```

## Pattern 3: Propagating authentication info to the backend

On successful authentication, pass `$webauthn_*` variables to the upstream as request headers.

```nginx
location /app/ {
    auth_webauthn            on;
    auth_webauthn_signin_url /login;
    auth_webauthn_set_header X-WebAuthn-User $webauthn_user_id;
    auth_webauthn_set_header X-WebAuthn-Cred $webauthn_credential_id;
    proxy_pass               http://backend_app;
}
```

The backend can identify the authenticated user via the `X-WebAuthn-User` header. Presuppose a configuration where the backend is not hit directly from outside (only via NGINX).

## Pattern 4: Multiple origins / subdomains

```nginx
auth_webauthn_rp_id  example.com;
auth_webauthn_origin https://example.com https://app.example.com;
```

Setting `rp_id` to the parent domain allows the same credential to be used from multiple origins under its registrable suffix. List all allowed origins in `auth_webauthn_origin`.

## Pattern 5: Signing the session JWT with an asymmetric key (ES256)

For when you want to verify with a public key between microservices.

```nginx
auth_webauthn_jwt_alg         ES256;
auth_webauthn_jwt_secret_file /etc/nginx/webauthn_es256.pem;  # PEM private key
```

The private key is EC P-256. NGINX derives the public key from the private key and verifies on its own.

## Wire formats

### `GET /webauthn/challenge`

Response (`application/json`):

```json
{
  "challenge": "rB2f...<base64url-32B>",
  "rpId": "example.com",
  "timeout": 60000,
  "userVerification": "preferred",
  "allowCredentials": []
}
```

The client passes this to `navigator.credentials.get({ publicKey: ... })`. Because `allowCredentials` is empty, discoverable credentials (resident keys) are presupposed.

### `POST /webauthn/verify`

Send the result of `navigator.credentials.get()` as JSON. What NGINX references is `id` and `response.clientDataJSON` / `response.authenticatorData` / `response.signature` (all base64url).

```json
{
  "id": "<base64url credential id>",
  "rawId": "<base64url>",
  "type": "public-key",
  "response": {
    "clientDataJSON": "<base64url>",
    "authenticatorData": "<base64url>",
    "signature": "<base64url>",
    "userHandle": "<base64url|null>"
  },
  "clientExtensionResults": {}
}
```

Success response (HTTP 200) — issues a session cookie:

```
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: webauthn_session=<JWT>; HttpOnly; SameSite=Strict; Path=/; Secure; Max-Age=3600
```

```json
{"ok":true,"user_id":"alice","exp":1729183600}
```

Failure response (HTTP 401) — uniform regardless of cause, to conceal credential existence:

```json
{"ok":false,"error":"E_ASSERTION"}
```

### Session JWT

The claims of the JWT issued via `Set-Cookie`:

```json
{
  "iss": "nginx-webauthn",
  "aud": "example.com",
  "sub": "alice",
  "cid": "<credential id (base64url)>",
  "iat": 1729180000,
  "exp": 1729183600,
  "jti": "<16B random base64url>"
}
```

The protection gate verifies the signature and `exp`.

## Setting up the login page

`examples/login/` contains a minimal implementation (`index.html` + `login.js`). It implements the flow `/webauthn/challenge` → `navigator.credentials.get()` → `/webauthn/verify`. The endpoints and the transition target can be configured via `<meta>` in `index.html`. See `examples/login/README.md` for details.

## Related documents

- [README.md](../README.md) — Overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md) — Directive reference
- [ADMIN_TOOL.md](ADMIN_TOOL.md) — CLI reference
- [SECURITY.md](SECURITY.md) — Verification items and attack resistance
