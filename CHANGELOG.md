# Changelog

All notable changes to this project are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

Initial release. Once a public key is registered in Redis, the full path of assertion verification → JWT cookie issuance → passing the protected gate works end to end.

### Added

#### NGINX module

- `auth_webauthn` location protection gate (JWT cookie verification at the access phase)
- `/webauthn/challenge` endpoint (`auth_webauthn_challenge_handler`) — issues a 32-byte CSPRNG challenge. When `?user_id=<id>` is given, returns that user's `allowCredentials` (an empty array even for unregistered users, to hide their existence)
- `auth_webauthn_user_verification` (`required` makes the UV flag mandatory at `/webauthn/verify`) / `auth_webauthn_challenge_rate_limit` (per-IP issuance rate limiting via Redis INCR)
- `/webauthn/verify` endpoint (`auth_webauthn_verify_handler`) — assertion verification and session JWT issuance
- Redis-based challenge store (`{prefix}chal:{raw}`). Atomic single-use consumption via `GETDEL` (Redis 6.2+) and native TTL expiry via `SET ... EX`. All nodes reference the same challenge set, so it scales out behind a load balancer
- Session JWT cookie issuance (HS256 / RS256 / ES256). `alg` is fixed at startup and `alg=none` is rejected
- Directive set (RP ID / origin / Redis connection / JWT and cookie settings / clone detection, etc.)
- NGINX variables `$webauthn_user_id` / `$webauthn_credential_id` / `$webauthn_auth_status` / `$webauthn_jwt_exp`
- Upstream propagation of authentication information via `auth_webauthn_set_header`
- Redirect on unauthenticated access via `auth_webauthn_signin_url` (401 when unset)

#### Assertion verification

- Validation of `type` / `challenge` / `origin` / `crossOrigin` in clientDataJSON
- `rpIdHash` matching, User Present (UP) flag check, and AT / ED flag rejection in authData
- Signature verification (ES256 / EdDSA / RS256)
- Clone detection via the sign counter (`strict` / `lax` / `off`)
- Uniform 401 response on failure to hide credential existence

#### Bundled CLI (auth-webauthn-admin)

- `register` / `revoke` / `list` / `show` subcommands
- Attestation verification (`none` / `packed` self-attestation)
- COSE public key → DER (SubjectPublicKeyInfo) conversion and registration into Redis

#### Data store

- Synchronous Redis client via hiredis (credential CRUD, user index)
- Stores public keys in DER form, eliminating CBOR/COSE processing at authentication time

#### Examples and distribution

- `examples/login/` — authentication page (HTML + JS)
- `examples/register/` — development registration server in Python (Flask + python-fido2)
- End-to-end demo reaching registration → login → protected page via docker compose
- nginx Docker image with the module bundled (`--with-compat` build)

### Known limitations

- User Verification (UV) is not required by default (UP is always required; UV can be made mandatory with `auth_webauthn_user_verification required`)
- The JWT `iss` / `aud` are issued but not validated at the protection gate (only the signature and `exp` are checked)
- Attestation supports only `none` / `packed` self (certificate-based attestation is not supported)
- `allowCredentials` is empty by default (assumes discoverable credentials; returned only when `?user_id=` is given)
- Credential registration is only via the CLI / Python sample (the in-NGINX registration handler is not implemented)

### Dependencies

- OpenSSL 3.0+ / hiredis / libcbor (CLI) / jansson (via nxe-json)
- submodules: `nxe-json` (JSON) / `nxe-jwx` (JWT)

## Related documents

- [README.md](README.md) — overview and quick start
- [docs/INSTALL.md](docs/INSTALL.md) — installation guide
