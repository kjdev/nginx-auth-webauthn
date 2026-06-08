# examples — run with docker compose

A self-contained example that reproduces **register → login → reach the
protected page** for `nginx-auth-webauthn` with a single `docker compose` run,
from building the module to starting Redis and the registration server.

```
examples/
├── compose.yaml          definition of the 3 services (nginx / register / redis)
├── docker/
│   ├── nginx/
│   │   ├── default.conf   server config mounted into conf.d (used by compose)
│   │   ├── jwt.key        sample HS256 secret (replace in production)
│   │   └── protected/     success page behind the auth gate
│   └── register/
│       └── Dockerfile     image for the development registration server (Flask)
├── login/                 login page (static frontend)
└── register/              registration page + Flask registration server
```

The nginx image (with the module built in) is built from the repository-root
`Dockerfile`; compose references it via `dockerfile: ../Dockerfile`.

## Prerequisites

- Docker / Docker Compose v2 (the `docker compose` subcommand)
- A **real authenticator** (a platform authenticator = Touch ID / Windows Hello,
  or a security key). The compose stack only provides the server side, not the
  authenticator.
- Access the browser at `http://localhost:8080`. `localhost` is a WebAuthn
  secure-context exception, so plain HTTP works.

## Start

```sh
cd examples
docker compose up --build
```

The first run takes a few minutes to build the module (dynamic `.so`) and the
bundled CLI.

## Browser walkthrough (E2E)

1. **Register**: open `http://localhost:8080/register/`, enter a user ID and
   click "Register a passkey". After the authenticator gesture you see
   `Registration succeeded: cid=...`.
2. **Log in**: open `http://localhost:8080/login/` and click "Sign in with a
   passkey". No user ID is needed because the credential is discoverable.
3. **Reach**: on success a session JWT cookie is issued and you are sent to `/`
   (the protected page), which shows "Authentication succeeded".
4. Opening `http://localhost:8080/` while unauthenticated redirects to
   `/login/` with a 302.

## CLI management and registration (auth-webauthn-admin)

The bundled CLI `auth-webauthn-admin` ships inside the nginx image and runs via
`docker compose exec`. Its job is **managing the credential store (list / show /
revoke)** and **ingesting an attestation produced by a real authenticator
(register)**. Generating keys or assertions is the authenticator's job
(browser / security key), so the CLI does not do it. To try it without a
browser at all, see "Test helper" below.

### List / show / revoke

```sh
docker compose exec nginx auth-webauthn-admin list \
    --user-id alice --redis redis:6379
docker compose exec nginx auth-webauthn-admin show \
    --credential-id <cid> --redis redis:6379
docker compose exec nginx auth-webauthn-admin revoke \
    --credential-id <cid> --redis redis:6379
```

### Register: ingest a browser-produced attestation

`register` takes the `navigator.credentials.create()` response JSON as input.
Without going through `register.py`, you can ingest the real thing produced by
the browser and register entirely from the CLI (if the DevTools virtual
authenticator is enabled, `create()` uses it).

In the browser Console (with `http://localhost:8080/` open), create a
credential and print the ingest JSON:

```js
const cred = await navigator.credentials.create({publicKey:{
  challenge:new Uint8Array(32), rp:{id:"localhost", name:"demo"},
  user:{id:new TextEncoder().encode("alice"), name:"alice", displayName:"alice"},
  pubKeyCredParams:[{type:"public-key",alg:-7},{type:"public-key",alg:-257}],
  authenticatorSelection:{residentKey:"required", userVerification:"preferred"},
  timeout:120000}});            // no attestation preference = fmt "none"
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b)))
  .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
console.log(JSON.stringify({id:cred.id, rawId:b64u(cred.rawId), type:cred.type,
  response:{clientDataJSON:b64u(cred.response.clientDataJSON),
            attestationObject:b64u(cred.response.attestationObject)}}));
```

Save the printed JSON to `cred.json` and ingest it:

```sh
docker compose exec -T nginx auth-webauthn-admin register \
    --user-id alice --rp-id localhost --redis redis:6379 --response-file - < cred.json
# -> registered: cid=... alg=ES256
```

> `register` treats clientData as a hash only (origin/challenge are not
> verified). The supported attestation formats are `none` and `packed` self
> only (`--require-attestation` defaults to `none`; x5c is rejected). The
> snippet above sets no attestation preference = `none`, so it passes. Create
> the credential with `residentKey:"required"` because `/login/` sends an empty
> `allowCredentials`. The Redis schema is identical to browser registration and
> `register.py`.

## Test helper: register/verify without a browser

To run register-through-verify fully headless, use the **authenticator
simulator** [`t/data/webauthn_tool.py`](../t/data/webauthn_tool.py) used by the
integration tests. It is not a shipped artifact — it is a test helper under
`t/` (ES256 only, depends on `cryptography`). It generates keys, attestations
and assertions the same way CI does. Run the following from `examples/`.

```sh
python3 -m pip install cryptography      # if not installed
TOOL=../t/data/webauthn_tool.py

# Register: generate key+cid -> attestation -> admin register
cid=$(python3 "$TOOL" keygen --out /tmp/wa-key.pem)
python3 "$TOOL" attestation --key /tmp/wa-key.pem --cid "$cid" \
    --rp-id localhost --origin http://localhost:8080 \
| docker compose exec -T nginx auth-webauthn-admin register \
    --user-id carol --rp-id localhost --redis redis:6379 --response-file -

# Verify (login equivalent): challenge -> assertion -> verify -> protected page
ch=$(curl -s http://localhost:8080/webauthn/challenge \
     | python3 -c 'import sys,json;print(json.load(sys.stdin)["challenge"])')
python3 "$TOOL" assertion --key /tmp/wa-key.pem --cid "$cid" \
    --rp-id localhost --origin http://localhost:8080 --challenge "$ch" \
| curl -s -i -c /tmp/wa-cookies.txt -X POST http://localhost:8080/webauthn/verify \
    -H 'Content-Type: application/json' --data-binary @-     # -> 200 + Set-Cookie
curl -s -i -b /tmp/wa-cookies.txt http://localhost:8080/      # -> 200 (protected page)
```

> **Reusing a DevTools virtual-authenticator key**: skip `keygen` and pass the
> exported `PrivateKey.pem` as `--key` and the **ID** from the Credentials
> table (base64url; convert it if it contains `+/=`) as `--cid` (the key must
> be EC P-256/ES256). This also goes through the simulator. Note that if that
> virtual authenticator is enabled, the "ingest a browser-produced attestation"
> path above is self-contained with the shipped tool only.

For using the CLI standalone (without docker) see [`tools/admin/`](../tools/admin/).

## About the single-origin layout

WebAuthn requires an exact origin (scheme + host + port) match. This example
aggregates registration, login, the protected target and every endpoint on
`http://localhost:8080`, and only proxies the registration API
(`/register/begin`, `/register/complete`) from nginx to Flask, keeping a single
origin. The `<meta>` defaults in `examples/login/` and `examples/register/`
(same-origin paths) work as-is.

## Notes

- `docker/nginx/jwt.key` is a sample HS256 secret. **Always replace it in
  production** (e.g. `openssl rand -hex 32 > jwt.key`).
- The Flask server under `register/` is for development and learning. It does
  not meet operational requirements such as authentication, rate limiting or
  CSRF protection (details in [`register/README.md`](register/README.md)).
- Settings (rp_id / origin / Redis endpoint, etc.) can be changed in
  `docker/nginx/default.conf` (the config compose mounts) and the environment
  variables in `compose.yaml`.

## See also

- [`login/README.md`](login/README.md) — login page details
- [`register/README.md`](register/README.md) — registration page and how
  it differs from the CLI
- [`docs/DIRECTIVES.md`](../docs/DIRECTIVES.md) — directive reference
