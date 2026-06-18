# Directives

This document describes all directives provided by the `nginx-auth-webauthn` module, as well as the NGINX variables exposed on successful authentication.

## Configuration examples

See [EXAMPLES.md](EXAMPLES.md) for complete configuration examples. The minimal configuration is in the "Quick start" section of [README.md](../README.md).

## Directive list

### Global / server configuration

| Directive | Context | Purpose |
|---|---|---|
| [auth_webauthn_rp_id](#auth_webauthn_rp_id) | http, server, location | RP ID (WebAuthn) |
| [auth_webauthn_rp_name](#auth_webauthn_rp_name) | http, server, location | RP display name (currently unused) |
| [auth_webauthn_origin](#auth_webauthn_origin) | http, server, location | Allowed origins |
| [auth_webauthn_challenge_ttl](#auth_webauthn_challenge_ttl) | http, server, location | Challenge expiration |
| [auth_webauthn_user_verification](#auth_webauthn_user_verification) | http, server, location | userVerification policy |
| [auth_webauthn_challenge_rate_limit](#auth_webauthn_challenge_rate_limit) | http, server, location | Challenge issuance rate limit |
| [auth_webauthn_redis](#auth_webauthn_redis) | http, server, location | Redis server |
| [auth_webauthn_redis_password](#auth_webauthn_redis_password) | http, server, location | Redis AUTH |
| [auth_webauthn_redis_db](#auth_webauthn_redis_db) | http, server, location | Redis DB number |
| [auth_webauthn_redis_timeout](#auth_webauthn_redis_timeout) | http, server, location | Redis timeout |
| [auth_webauthn_redis_key_prefix](#auth_webauthn_redis_key_prefix) | http, server, location | Redis key prefix |
| [auth_webauthn_jwt_secret_file](#auth_webauthn_jwt_secret_file) | http, server, location | JWT signing key file |
| [auth_webauthn_jwt_alg](#auth_webauthn_jwt_alg) | http, server, location | JWT signing algorithm |
| [auth_webauthn_jwt_ttl](#auth_webauthn_jwt_ttl) | http, server, location | JWT expiration |
| [auth_webauthn_jwt_cookie_name](#auth_webauthn_jwt_cookie_name) | http, server, location | Cookie name |
| [auth_webauthn_jwt_cookie_domain](#auth_webauthn_jwt_cookie_domain) | http, server, location | Cookie Domain |
| [auth_webauthn_jwt_cookie_path](#auth_webauthn_jwt_cookie_path) | http, server, location | Cookie Path |
| [auth_webauthn_jwt_cookie_secure](#auth_webauthn_jwt_cookie_secure) | http, server, location | Cookie Secure |
| [auth_webauthn_jwt_cookie_samesite](#auth_webauthn_jwt_cookie_samesite) | http, server, location | Cookie SameSite |
| [auth_webauthn_clone_detection](#auth_webauthn_clone_detection) | http, server, location | Clone-detection policy |

### Location-specific configuration

| Directive | Context | Purpose |
|---|---|---|
| [auth_webauthn](#auth_webauthn) | server, location | Enable the protection gate |
| [auth_webauthn_signin_url](#auth_webauthn_signin_url) | server, location | Redirect target when unauthenticated |
| [auth_webauthn_set_header](#auth_webauthn_set_header) | server, location | Headers added toward the backend |
| [auth_webauthn_challenge_handler](#auth_webauthn_challenge_handler) | location | Challenge issuance endpoint |
| [auth_webauthn_verify_handler](#auth_webauthn_verify_handler) | location | Assertion verification endpoint |

> Configuration inheritance: values set in `http` / `server` are inherited by lower blocks; redefining them in a lower block overrides the inherited value.

## NGINX variables

For requests that pass the authentication gate (`auth_webauthn on`), the following variables are available. Reference them in the value of `auth_webauthn_set_header`, in log formats, in `proxy_set_header`, and so on.

| Variable | Content |
|---|---|
| `$webauthn_user_id` | Authenticated user ID (JWT `sub`). Has a value only on successful authentication |
| `$webauthn_credential_id` | Credential ID used for authentication (base64url, JWT `cid`). Only on successful authentication |
| `$webauthn_auth_status` | Authentication status. One of `authenticated` / `unauthenticated` / `expired` / `invalid` |
| `$webauthn_jwt_exp` | JWT `exp` (Unix time). Only on successful authentication |

Values of `$webauthn_auth_status`:

- `authenticated` — both JWT verification and expiration passed
- `unauthenticated` — `auth_webauthn off`, or no JWT present in the cookie
- `invalid` — JWT decoding / signature verification failed, or `aud` (=`rp_id`) / `iss` (=`nginx-webauthn`) verification failed
- `expired` — the JWT `exp` is past the current time

---

## Directive details

### auth_webauthn

```
Syntax:  auth_webauthn on | off;
Default: auth_webauthn off;
Context: server, location
```

Protects the location with Passkey (WebAuthn). When `on`, the request undergoes JWT cookie verification at the access phase, and if unauthenticated returns a redirect (302) to the `auth_webauthn_signin_url` target or a 401.

### auth_webauthn_rp_id

```
Syntax:  auth_webauthn_rp_id <domain>;
Default: -
Context: http, server, location
```

Specifies the WebAuthn Relying Party ID (RP ID). It must match the domain of `auth_webauthn_origin` or be a registrable suffix of it. It is used in two places:

- The `rpId` field of the `/webauthn/challenge` response
- During Assertion verification, the `rpIdHash` in authData is compared against `SHA-256(rp_id)`

### auth_webauthn_rp_name

```
Syntax:  auth_webauthn_rp_name <string>;
Default: -
Context: http, server, location
```

The RP display name. **Not referenced in the current version (reserved for a future registration-handler implementation).** The RP name shown in the browser UI during registration is specified on the registration-flow side that uses the bundled CLI / Python sample.

### auth_webauthn_origin

```
Syntax:  auth_webauthn_origin <url> [<url>...];
Default: -
Context: http, server, location
```

Specifies the allowed origins (multiple allowed). The `origin` field of clientDataJSON is verified by exact match. Match including scheme, host, and port (e.g. `https://example.com`, `https://example.com:8443`).

### auth_webauthn_challenge_ttl

```
Syntax:  auth_webauthn_challenge_ttl <time>;
Default: auth_webauthn_challenge_ttl 60s;
Context: http, server, location
```

The expiration of an issued challenge. This value is also reflected in the `timeout` (milliseconds) of the `/webauthn/challenge` response. Recommended range 60–300 seconds.

### auth_webauthn_user_verification

```
Syntax:  auth_webauthn_user_verification required | preferred | discouraged;
Default: auth_webauthn_user_verification preferred;
Context: http, server, location
```

The WebAuthn userVerification policy. It is reflected verbatim in the `userVerification` field of the `/webauthn/challenge` response.

- `required` — User verification (biometrics, PIN, etc.) is mandatory. `/webauthn/verify` **rejects with 401 when the asserted UV flag is not set**.
- `preferred` — Request UV when possible, but accept assertions without it (no enforcement on verify).
- `discouraged` — Do not request UV.

Only `required` enforces the UV flag on verify; the others merely advertise the preference in the challenge response. The UP (User Present) flag is always required regardless of policy.

### auth_webauthn_challenge_rate_limit

```
Syntax:  auth_webauthn_challenge_rate_limit off | <max> [<window>];
Default: auth_webauthn_challenge_rate_limit off;
Context: http, server, location
```

Limits `/webauthn/challenge` issuance per client IP. Allows up to `<max>` requests per `<window>` (a time value, default 60s); exceeding it returns `429 Too Many Requests`. `off` (or the default) disables it.

```nginx
auth_webauthn_challenge_rate_limit 10 60s;   # up to 10 per 60 seconds
```

The counter is held in Redis (`{prefix}ratelimit:challenge:{ip}`, INCR + EXPIRE) so it is shared across nodes. Being a fixed-window counter, it may allow a burst of up to 2×`max` across a window boundary. If the counter cannot be read, issuance proceeds (fail-open).

The `{ip}` in the key is the TCP peer address (equivalent to `$remote_addr`). When this module runs at the edge that is the real client IP, but behind a CDN / load balancer all clients collapse to the LB's single IP, effectively globalizing the limit (one client exhausting the quota locks out everyone). When deployed behind a proxy, also configure the `realip` module (`set_real_ip_from` + `real_ip_header`). `realip` rewrites `$remote_addr` to the real client IP and this module reads that value, so per-client limiting works with no extra configuration.

### auth_webauthn_redis

```
Syntax:  auth_webauthn_redis <host>:<port>;
Default: -
Context: http, server, location
```

The connection target of the Redis server. Stores and looks up credentials (public keys).

### auth_webauthn_redis_password

```
Syntax:  auth_webauthn_redis_password <string> | file:<path>;
Default: -
Context: http, server, location
```

The Redis AUTH password. With the `file:<path>` form it can be read from an external file (permissions 0600 recommended). If unspecified, AUTH is not performed.

### auth_webauthn_redis_db

```
Syntax:  auth_webauthn_redis_db <int>;
Default: auth_webauthn_redis_db 0;
Context: http, server, location
```

The Redis database number.

### auth_webauthn_redis_timeout

```
Syntax:  auth_webauthn_redis_timeout <time>;
Default: auth_webauthn_redis_timeout 100ms;
Context: http, server, location
```

The timeout for Redis connection and command responses.

### auth_webauthn_redis_key_prefix

```
Syntax:  auth_webauthn_redis_key_prefix <string>;
Default: auth_webauthn_redis_key_prefix "webauthn:";
Context: http, server, location
```

The prefix for Redis keys. Credentials are stored as `{prefix}cred:{credential_id}` and the user index as `{prefix}user:{user_id}:creds`. Make it match the `--key-prefix` of the bundled CLI.

### auth_webauthn_jwt_secret_file

```
Syntax:  auth_webauthn_jwt_secret_file <path>;
Default: -
Context: http, server, location
```

The JWT signing key file. Its content differs depending on `auth_webauthn_jwt_alg`:

- `HS256` — a random key of 32 bytes or more (raw byte sequence)
- `RS256` / `ES256` — a private key in PEM format

Permissions 0600 are recommended. It is used both for JWT signing on successful Assertion verification and for JWT verification at the protection gate (for asymmetric keys, the public key derived from the private key).

### auth_webauthn_jwt_alg

```
Syntax:  auth_webauthn_jwt_alg HS256 | RS256 | ES256;
Default: auth_webauthn_jwt_alg HS256;
Context: http, server, location
```

The signing algorithm of the session JWT. It is fixed at startup, and the `alg` at verification is also fixed to this value (the `alg=none` attack is rejected).

### auth_webauthn_jwt_ttl

```
Syntax:  auth_webauthn_jwt_ttl <time>;
Default: auth_webauthn_jwt_ttl 1h;
Context: http, server, location
```

The expiration of the issued JWT. It becomes `exp = iat + jwt_ttl`, and the same number of seconds is set in the cookie's `Max-Age`.

### auth_webauthn_jwt_cookie_name

```
Syntax:  auth_webauthn_jwt_cookie_name <string>;
Default: auth_webauthn_jwt_cookie_name webauthn_session;
Context: http, server, location
```

The session cookie name.

### auth_webauthn_jwt_cookie_domain

```
Syntax:  auth_webauthn_jwt_cookie_domain <domain>;
Default: -
Context: http, server, location
```

The cookie's `Domain` attribute. If unspecified, the attribute is not added and the browser binds it to the current host.

### auth_webauthn_jwt_cookie_path

```
Syntax:  auth_webauthn_jwt_cookie_path <path>;
Default: auth_webauthn_jwt_cookie_path /;
Context: http, server, location
```

The cookie's `Path` attribute.

### auth_webauthn_jwt_cookie_secure

```
Syntax:  auth_webauthn_jwt_cookie_secure on | off;
Default: auth_webauthn_jwt_cookie_secure on;
Context: http, server, location
```

The cookie's `Secure` attribute. When `on`, the cookie is sent only over HTTPS. Because WebAuthn presupposes a secure context (HTTPS), keep it `on` in production.

### auth_webauthn_jwt_cookie_samesite

```
Syntax:  auth_webauthn_jwt_cookie_samesite strict | lax | none;
Default: auth_webauthn_jwt_cookie_samesite strict;
Context: http, server, location
```

The cookie's `SameSite` attribute (added as `Strict` / `Lax` / `None`). When using `none`, `Secure` is required (a browser requirement).

### auth_webauthn_clone_detection

```
Syntax:  auth_webauthn_clone_detection strict | lax | off;
Default: auth_webauthn_clone_detection strict;
Context: http, server, location
```

The behavior when the authenticator's sign counter goes backward or stays the same (clone detection):

- `strict` — reject authentication (401)
- `lax` — only log, but let authentication through
- `off` — do not check at all (not recommended)

When the presented counter and the stored value are **both 0**, it is treated as a counter-less authenticator (many Passkeys) and allowed under all policies, including `strict`.

### auth_webauthn_signin_url

```
Syntax:  auth_webauthn_signin_url <url>;
Default: -
Context: server, location
```

The redirect target when unauthenticated. When specified, returns a 302 with `Location: <url>`. When unspecified, returns a 401.

### auth_webauthn_set_header

```
Syntax:  auth_webauthn_set_header <name> <value>;
Default: -
Context: server, location
```

Headers added to the request toward the upstream on successful authentication (multiple allowed). The value can use a complex value containing `$webauthn_*` variables.

```nginx
auth_webauthn_set_header X-WebAuthn-User $webauthn_user_id;
auth_webauthn_set_header X-WebAuthn-Cred $webauthn_credential_id;
```

### auth_webauthn_challenge_handler

```
Syntax:  auth_webauthn_challenge_handler on | off;
Default: auth_webauthn_challenge_handler off;
Context: location
```

Makes this location act as the `/webauthn/challenge` endpoint (challenge issuance). The client performs a GET and receives the following JSON (`application/json`):

```json
{
  "challenge": "<base64url-32B>",
  "rpId": "<auth_webauthn_rp_id>",
  "timeout": 60000,
  "userVerification": "preferred",
  "allowCredentials": []
}
```

`userVerification` reflects the [auth_webauthn_user_verification](#auth_webauthn_user_verification) value. `timeout` is `auth_webauthn_challenge_ttl` converted to milliseconds.

`allowCredentials` is an empty array by default (presupposing discoverable credentials / resident keys). Adding the query `?user_id=<id>` returns that user's registered credential ids:

```json
"allowCredentials": [
  { "type": "public-key", "id": "<base64url-credential-id>" }
]
```

This lets non-discoverable authenticators be selected. An unknown, empty, or absent `user_id` all return an empty array, so the endpoint never reveals whether a user exists (enumeration defense).

Because the issued challenge is stored in Redis (`{prefix}chal:{raw}`, `SET ... EX`), the `auth_webauthn_redis` setting is also required in this location. If the Redis connection fails, it returns 500. Use [auth_webauthn_challenge_rate_limit](#auth_webauthn_challenge_rate_limit) to cap issuance per IP.

### auth_webauthn_verify_handler

```
Syntax:  auth_webauthn_verify_handler on | off;
Default: auth_webauthn_verify_handler off;
Context: location
```

Makes this location act as the `/webauthn/verify` endpoint (Assertion verification). The client POSTs the result of `navigator.credentials.get()` as JSON.

On success it returns 200 + `Set-Cookie` (the session JWT) + `{"ok":true,...}`. On failure, to conceal credential existence, it returns a uniform 401 + `{"ok":false,"error":"E_ASSERTION"}` regardless of the cause. See [EXAMPLES.md](EXAMPLES.md) for request/response details.

## Related documents

- [README.md](../README.md) — Overview and quick start
- [INSTALL.md](INSTALL.md) — Installation guide
- [EXAMPLES.md](EXAMPLES.md) — Configuration patterns and wire formats
- [ADMIN_TOOL.md](ADMIN_TOOL.md) — `auth-webauthn-admin` CLI reference
- [SECURITY.md](SECURITY.md) — Verification items and attack resistance
