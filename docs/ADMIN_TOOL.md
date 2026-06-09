# auth-webauthn-admin Reference

`auth-webauthn-admin` is the bundled CLI tool for registering, revoking, listing, and inspecting WebAuthn credentials (public keys) in Redis.

The NGINX module itself handles the authentication gate (Assertion verification + JWT cookie issuance) and does not handle credential **registration**. For production, use this CLI as the registration method. For learning and testing, the Python sample under `examples/register/` is also available (same Redis schema as the CLI).

## Build

```bash
cd tools/admin && make
```

This produces `tools/admin/auth-webauthn-admin`. The CLI links against libcbor (attestationObject / COSE parsing), OpenSSL (COSE→DER conversion), hiredis (Redis), and jansson (JSON, via nxe-json).

## Common options

Available on all subcommands.

```
--redis=<host:port>          Redis server (required)
--redis-password=<s|file:p>  Redis AUTH (literal or file:<path>)
--redis-db=<int>             Redis DB number (default 0)
--redis-timeout=<ms>         connection/command timeout (default 100)
--key-prefix=<string>        Redis key prefix (default "webauthn:")
-h, --help                   show help; --version shows the version
```

Make `--key-prefix` match `auth_webauthn_redis_key_prefix` on the NGINX side.

## Subcommands

### register — Register a credential

Reads a file containing the `AttestationResponse` (returned by the browser's `navigator.credentials.create()`) as JSON, extracts the public key from the attestationObject, and registers it in Redis.

```
auth-webauthn-admin register \
    --user-id=<id> \
    --response-file=<path> \
    --rp-id=<domain> \
    [--require-attestation=none|packed] \
    [--origin=<url>] \
    [--transports=<csv>] \
    <common options>
```

| Option | Required | Description |
|---|---|---|
| `--user-id` | ✓ | In-application user ID |
| `--response-file` | ✓ | Path to the AttestationResponse JSON. `-` for standard input |
| `--rp-id` | ✓ | Expected RP ID. Compared against the rpIdHash in authData |
| `--require-attestation` | | `none` (default) or `packed`. The verification level |
| `--origin` | | Accepted but not verified (because the CLI has no challenge store) |
| `--transports` | | Override transports (e.g. `usb,nfc,internal`) |

Processing: parse JSON → base64url-decode clientDataJSON/attestationObject → parse the attestationObject (CBOR) → extract authData → `SHA-256(clientDataJSON)` → attestation verification (rpIdHash comparison + policy) → convert the COSE public key to DER (SubjectPublicKeyInfo) → HSET into `{prefix}cred:{cid}` + SADD into `{prefix}user:{uid}:creds`.

Output on success (cid is the first 12 characters + `...`):

```
registered: cid=AQIDBAUGBwgJ... alg=ES256
```

`alg` is one of `ES256` / `RS256` / `EdDSA`.

> The CLI does not verify the `origin` / `type` / `challenge` of clientDataJSON (because a challenge is meaningful only at authentication time). The origin legitimacy at registration is ensured by the network path and operations.

### revoke — Revoke a credential

```
auth-webauthn-admin revoke --credential-id=<b64url> <common options>
```

DELs `{prefix}cred:{cid}` and SREMs it from the user index `{prefix}user:{uid}:creds`. Output on success:

```
revoked: cid=AQIDBAUGBwgJ...
```

If the target does not exist, it prints `error: no such credential` to standard error and exits with code 1.

### list — List a user's credentials

```
auth-webauthn-admin list --user-id=<id> <common options>
```

SMEMBERs `{prefix}user:{uid}:creds` and displays a table summarizing each credential.

```
CREDENTIAL_ID                               ALG    SIGN_COUNT  CREATED_AT
AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA  ES256  42          2026-04-17T10:00:00Z
```

Credentials that are registered in the index but whose entity is missing are shown as a `(missing)` row.

### show — Credential details

```
auth-webauthn-admin show --credential-id=<b64url> <common options>
```

Displays all fields of `{prefix}cred:{cid}` in a human-readable form.

```
credential_id: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA
user_id:       alice
alg:           ES256 (-7)
sign_count:    42
created_at:    2026-04-17T10:00:00Z
last_used_at:  2026-04-17T12:34:56Z
aaguid:        00000000-0000-0000-0000-000000000000
transports:    usb,nfc
public_key:    91 bytes (DER SubjectPublicKeyInfo)
```

Fields with no value are shown as `-` (e.g. a `last_used_at` of 0, an unregistered `aaguid`/`transports`).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error (Redis connection failure, target absent, verification failure, etc.) |
| 2 | Argument error (missing required option, invalid value) |

## Attestation verification policy

Specify the required level with `--require-attestation`.

- `none` (default) — does not verify attestation. Easy to operate because many real Passkeys return `fmt: none`
- `packed` — verifies only `packed` self-attestation (a signature by the public key itself). A `fmt` other than `packed`, or one with an x5c certificate, is rejected

`packed` with a certificate / `tpm` / `android-safetynet` / `apple` / `fido-u2f` are not supported.

## Version

```bash
$ auth-webauthn-admin --version
auth-webauthn-admin 0.1.0
```

## Related documents

- [README.md](../README.md) — Overview and quick start
- [INSTALL.md](INSTALL.md) — Installation guide
- [DIRECTIVES.md](DIRECTIVES.md) — Directive reference
- [EXAMPLES.md](EXAMPLES.md) — Configuration patterns
