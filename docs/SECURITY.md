# Security

This document summarizes the WebAuthn Assertion verification items implemented by `nginx-auth-webauthn`, its attack resistance, operational notes, and the known limitations of the current version.

## Assertion verification items

The following are verified in order against the Assertion received at `/webauthn/verify`. Any failure results in a uniform 401.

| Item | Content |
|---|---|
| `type` | The `type` of clientDataJSON is `webauthn.get` |
| `challenge` | The `challenge` of clientDataJSON matches an issued challenge byte-for-byte and has not expired |
| `origin` | The `origin` of clientDataJSON exactly matches one of `auth_webauthn_origin` |
| `crossOrigin` | Reject `crossOrigin: true` |
| AT / ED flags | Reject if the Assertion's authData contains attestedCredentialData (AT) / extensions (ED) |
| `rpIdHash` | The first 32 bytes of authData match `SHA-256(auth_webauthn_rp_id)` |
| UP flag | The User Present (0x01) bit is set |
| sign counter | Judged according to the clone-detection policy (see below) |
| signature | `authenticatorData ‖ SHA-256(clientDataJSON)` is verified with the registered public key |

## Attack resistance

### Replay attacks

A challenge is generated as 32 bytes with a CSPRNG (`RAND_bytes`) and stored in Redis (`{prefix}chal:{raw}`). At `/webauthn/verify`, it is retrieved and deleted **atomically** with `GETDEL` (Redis 6.2+) (consume), so even if the same Assertion is resent, the second time no matching challenge exists and it fails. Expired challenges also become invalid after the native TTL (`auth_webauthn_challenge_ttl`) of `SET ... EX` elapses.

### Origin / RP ID verification

- The `origin` is matched against the allowlist by exact match, excluding Assertions routed through phishing sites
- The `rpIdHash` is compared against `SHA-256(rp_id)`, preventing reuse of credentials intended for a different RP

### Clone detection (sign counter)

If the sign counter returned by the authenticator has not increased beyond the stored value, credential cloning is suspected. You can choose the behavior with `auth_webauthn_clone_detection`:

- `strict` (default) — 401 if the counter has not increased
- `lax` — only log and let it through
- `off` — do not check

When the counter is 0 on both sides, it is treated as a counter-less authenticator (many Passkeys) and allowed under all policies.

### alg=none / algorithm pinning

The signing algorithm of the session JWT is fixed at startup by `auth_webauthn_jwt_alg`, and the `alg` at verification is fixed to this value too. `alg=none` or substitution with a different algorithm is rejected.

### Oracle avoidance (uniform response)

On failure of `/webauthn/verify`, regardless of cause (credential absent / signature mismatch / challenge expired / Redis failure, etc.), it returns a uniform 401 + `{"ok":false,"error":"E_ASSERTION"}`. This avoids leaking the existence of a credential or the failure reason to an attacker.

## Session JWT / cookie

- The cookie is by default set with `HttpOnly; Secure; SameSite=Strict; Path=/`. `HttpOnly` is always added and cannot be read from JavaScript
- Manage the signing key (`auth_webauthn_jwt_secret_file`) with permissions 0600. For HS256, use a random key of 32 bytes or more
- The protection gate verifies the signature, `aud`, `iss`, and `exp`. Exceeding `exp` is rejected as `expired`; a mismatch of `aud` (=`auth_webauthn_rp_id`) or `iss` (=`nginx-webauthn`) is rejected as `invalid`
- When using `SameSite=None`, `Secure` is required

## Security of the Redis connection

- Place Redis inside a trusted network. Do not expose it
- Set AUTH with `auth_webauthn_redis_password`, and you can externalize the password with `file:<path>` (permissions 0600)
- Only public keys are stored; the private key stays inside the authenticator (by WebAuthn design, the server does not hold the private key)

## Logging and privacy

- The details of verification failures are recorded in error_log, but only the uniform response is returned to the client
- When emitting `$webauthn_user_id` and the like to the access log, note that the user ID can be PII

## Operational notes

- **HTTPS required**: WebAuthn works only in a secure context (except `localhost`)
- Always confirm that the domains of `rp_id` and `origin` are consistent (a mismatch is a cause of all Assertions failing)
- Build key / Redis-password rotation procedures into your operations
- When multiple `server` / `location` blocks share one `auth_webauthn_jwt_secret_file` (HMAC secret), sessions are separated across apps by `aud` (=`auth_webauthn_rp_id`). Give apps that must stay isolated distinct `rp_id` values; sharing the same `rp_id` lets a session cookie work across them

## Known limitations (current version)

The following are implementation limitations of the current version. Be aware of them in operation.

- **User Verification (UV) is not enforced by default**: UP (User Present) is always required. UV (user verification via biometrics / PIN) can be enforced at `/webauthn/verify` by setting `auth_webauthn_user_verification required` (assertions without the UV flag get 401). With the default `preferred`, the challenge response merely advertises `preferred` and assertions without UV still pass. Set `required` if you need multi-factor-equivalent assurance
- **Attestation only at registration**: only `none` or `packed` self-attestation is supported. Certificate-based attestation (`tpm` / `apple` / `fido-u2f`, etc.) is not supported
- **`allowCredentials` is empty by default**: it presupposes discoverable credentials (resident keys). Fetching the challenge with `?user_id=<id>` returns that user's credential ids (an unknown user still gets an empty array, so existence is not leaked)

## Related documents

- [DIRECTIVES.md](DIRECTIVES.md) — Directive reference
- [EXAMPLES.md](EXAMPLES.md) — Configuration patterns
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — Troubleshooting
