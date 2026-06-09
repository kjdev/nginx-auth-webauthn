# nginx auth_webauthn module

> ⚠️ **Experimental**: This module is an experimental implementation. Validate thoroughly before any production use. Interfaces such as directives and the Redis schema may change without notice.

## Overview

### About this module

This nginx module is a dynamic module that handles passwordless authentication (Passkey / FIDO2 security keys) based on the [Web Authentication API (WebAuthn)](https://www.w3.org/TR/webauthn-3/) entirely at the edge (NGINX).

It lets you protect existing locations with Passkey authentication without modifying the backend application.

**Key features**:

- Assertion verification with Passkey (WebAuthn) handled entirely at the NGINX layer
- Challenge (nonce) generation and management (Redis, single-use via `GETDEL`)
- Persistent storage of credentials (public keys) in Redis
- JWT cookie issuance on successful authentication, with protection-gate processing at the access phase
- Propagation of authentication information to the backend (`auth_webauthn_set_header`)
- Clone-detection (sign counter rollback) policy
- Supported algorithms: ES256 / EdDSA / RS256 for verification, HS256 / RS256 / ES256 for session JWT signing
- Bundled CLI tool `auth-webauthn-admin` for registration, revocation, and listing

**License**: MIT License

### Security

This module implements Assertion verification based on WebAuthn specification §7.2 (Verifying an Authentication Assertion). See [docs/SECURITY.md](docs/SECURITY.md) for the verification items, attack resistance, and known limitations.

## Quick start

See [docs/INSTALL.md](docs/INSTALL.md) for installation.

### Minimal configuration

```nginx
http {
    auth_webauthn_rp_id           example.com;
    auth_webauthn_origin          https://example.com;
    auth_webauthn_redis           127.0.0.1:6379;
    auth_webauthn_jwt_secret_file /etc/nginx/webauthn_jwt.key;

    server {
        listen 443 ssl;
        server_name example.com;

        location = /webauthn/challenge { auth_webauthn_challenge_handler on; }
        location = /webauthn/verify    { auth_webauthn_verify_handler    on; }

        location /admin/ {
            auth_webauthn            on;
            auth_webauthn_signin_url /login;
            auth_webauthn_set_header X-WebAuthn-User $webauthn_user_id;
            proxy_pass               http://backend_admin;
        }
    }
}
```

See [docs/EXAMPLES.md](docs/EXAMPLES.md) for detailed configuration patterns and [docs/DIRECTIVES.md](docs/DIRECTIVES.md) for each directive.

### Credential registration

Since the in-NGINX registration handler is not yet implemented, register credentials with the bundled CLI or the Python sample.

```bash
# After calling navigator.credentials.create() in the browser and saving the result as JSON:
auth-webauthn-admin register \
    --user-id=alice \
    --response-file=./attestation-response.json \
    --rp-id=example.com \
    --origin=https://example.com \
    --redis=127.0.0.1:6379
```

See [docs/ADMIN_TOOL.md](docs/ADMIN_TOOL.md) for CLI details. For learning and testing, the Python sample under `examples/register/` is also available.

### Try it out (docker compose)

`examples/` contains a docker compose demo that reproduces the registration → login → reaching a protected page flow in one shot.

```bash
cd examples && docker compose up --build   # http://localhost:8080
```

## Documentation

### For users

- [docs/INSTALL.md](docs/INSTALL.md) — Installation guide
- [docs/DIRECTIVES.md](docs/DIRECTIVES.md) — Directive and variable reference
- [docs/EXAMPLES.md](docs/EXAMPLES.md) — Configuration patterns and wire formats
- [docs/ADMIN_TOOL.md](docs/ADMIN_TOOL.md) — `auth-webauthn-admin` CLI reference
- [docs/SECURITY.md](docs/SECURITY.md) — Verification items, attack resistance, and known limitations
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — Troubleshooting
