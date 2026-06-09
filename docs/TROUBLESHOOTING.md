# Troubleshooting

This document summarizes common configuration mistakes and steps to isolate authentication failures.

## Check first

1. **Are you serving over HTTPS?** — WebAuthn requires a secure context. Over HTTP other than `localhost`, `navigator.credentials` itself does not work
2. **Are `rp_id` and `origin` consistent?** — `auth_webauthn_rp_id` is the origin's domain (or a registrable suffix). A mismatch is a cause of all Assertions failing
3. **Check the `error_log`** — `/webauthn/verify` does not return the failure reason to the client (uniform 401), so check the cause in error_log. `error_log ... info;` is recommended while isolating

## `/webauthn/verify` returns 401

Because failures are uniformly `{"ok":false,"error":"E_ASSERTION"}`, check the following in order.

| Cause | How to check / fix |
|---|---|
| Origin mismatch | Register the browser's origin in `auth_webauthn_origin` by exact match (scheme + host + port) |
| rp_id mismatch | Whether `auth_webauthn_rp_id` matches the browser's domain. It must also match the rp-id used at registration |
| Challenge expired | If `navigator.credentials.get()` takes time, it exceeds `auth_webauthn_challenge_ttl`. Extend the TTL (60–300s) |
| Reusing a challenge | Resending the same challenge fails because it has been consumed. Always fetch a fresh one from `/webauthn/challenge` |
| Credential not registered | Check Redis with `auth-webauthn-admin list --user-id=<id>` / `show --credential-id=<cid>` |
| key-prefix mismatch | Make NGINX's `auth_webauthn_redis_key_prefix` match the CLI's `--key-prefix` |
| Clone detection | A sign-counter rollback is rejected under `strict`. Check the authenticator's behavior and use `lax` if needed |
| Signature verification failure | Whether the registered public key (alg) and the Assertion's alg match. Check alg with `show` |
| Redis connection failure | See "Cannot connect to Redis" below |

## Protection gate returns 401 / 302

When you cannot pass an `auth_webauthn on` location.

| Cause | Fix |
|---|---|
| No cookie | Whether login succeeded and `Set-Cookie` was returned. Whether the cookie's `Path` / `Domain` are consistent with the access target |
| Signature verification failure | Whether `auth_webauthn_jwt_secret_file` / `auth_webauthn_jwt_alg` are identical at issuance and at verification (whether the configuration differs between servers) |
| Expired (`expired`) | `auth_webauthn_jwt_ttl` exceeded. Re-login required |
| `Secure` cookie not sent | You are accessing over HTTP. Retry over HTTPS |
| 302 loop with `signin_url` | Whether the login page itself is under `auth_webauthn on` |

Emitting `$webauthn_auth_status` to the access log lets you isolate the state (`unauthenticated` / `invalid` / `expired` / `authenticated`):

```nginx
log_format webauthn '$remote_addr $status webauthn=$webauthn_auth_status user=$webauthn_user_id';
access_log /var/log/nginx/access.log webauthn;
```

## Configuration error in `nginx -t`

| Error | Cause |
|---|---|
| `auth_webauthn` directive is not allowed here | Written in the `http` block. It is for `server` / `location` only |
| Invalid `jwt_alg` | Something other than `HS256` / `RS256` / `ES256` specified |

## Cannot connect to Redis

- Check the destination and reachability of `auth_webauthn_redis <host>:<port>`
- Whether `auth_webauthn_redis_timeout` is too short (default 100ms). Extend it in environments with network latency
- If the Redis requires AUTH, set `auth_webauthn_redis_password`
- Whether the DB number (`auth_webauthn_redis_db`) matches the one at registration (CLI `--redis-db`)
- Because challenges are stored in Redis, a Redis connection is required at both `/webauthn/challenge` (issuance) and `/webauthn/verify` (consume). If the connection fails, it returns 500
- `GETDEL` requires Redis 6.2 or later. Below that, challenge consume fails and verify returns 401. Check the Redis version
- Connectivity check from the CLI: `auth-webauthn-admin list --user-id=<id> --redis=<host:port>`

## `navigator.credentials.get()` fails on the browser side

- Is it HTTPS (except `localhost`)
- Whether `rpId` matches the current domain (the `rpId` of the challenge response)
- Whether a registered credential exists. Because `allowCredentials` is empty, it must be registered as a discoverable credential (resident key)
- Whether the authenticator was canceled (a timeout of the user interaction)

## Registration (CLI) fails

| Symptom | Fix |
|---|---|
| `error: no such credential` (revoke) | Whether the credential-id is correct. Check with `list` |
| Rejected for rpId mismatch | Whether `--rp-id` matches the rpIdHash of the AttestationResponse |
| Attestation rejected | You passed an x5c-attached / non-packed credential with `--require-attestation=packed`. Try `none` |
| JSON parse failure | Whether `--response-file` is a valid AttestationResponse JSON |

## Related documents

- [DIRECTIVES.md](DIRECTIVES.md) — Directive reference
- [EXAMPLES.md](EXAMPLES.md) — Configuration patterns
- [ADMIN_TOOL.md](ADMIN_TOOL.md) — CLI reference
- [SECURITY.md](SECURITY.md) — Verification items and attack resistance
