#!/usr/bin/env python3
"""Development-only WebAuthn registration server for nginx-auth-webauthn.

This is a learning / reference implementation. It performs a registration
ceremony with python-fido2, then writes the resulting credential into Redis in
the EXACT same schema the NGINX module reads (see docs/ARCHITECTURE.md 5.1 and
src/ngx_auth_webauthn_credential.c). For production registration use the CLI
``tools/admin/auth-webauthn-admin`` instead.

Configuration via environment variables (all optional, defaults shown):
    WEBAUTHN_RP_ID       localhost
    WEBAUTHN_RP_NAME     nginx-auth-webauthn example
    WEBAUTHN_ORIGIN      http://localhost:5000
    WEBAUTHN_KEY_PREFIX  webauthn:
    REDIS_URL            redis://127.0.0.1:6379/0
    FLASK_SECRET_KEY     (random per process if unset; set it to keep sessions)
"""

import base64
import os

import redis as redis_lib
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fido2 import features
from fido2.server import Fido2Server

# fido2 1.2+ defaults to the legacy dict format and only base64url-decodes the
# WebAuthn JSON fields (rawId / clientDataJSON / attestationObject) when this
# mapping is enabled. register.js sends that JSON shape, so opt in explicitly;
# otherwise from_dict() does bytes(<str>) and raises "string argument without
# an encoding".
features.webauthn_json_mapping.enabled = True
from fido2.webauthn import (
    AttestationConveyancePreference,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from flask import Flask, jsonify, request, send_from_directory, session

HERE = os.path.dirname(os.path.abspath(__file__))

RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "nginx-auth-webauthn example")
ORIGIN = os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:5000")
KEY_PREFIX = os.environ.get("WEBAUTHN_KEY_PREFIX", "webauthn:")
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

# COSE curve id -> cryptography curve (EC2 keys).
_EC_CURVES = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1}

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)

# Request attestation and discoverable credentials so examples/login (which
# sends an empty allowCredentials list) can resolve the user from the key alone.
server = Fido2Server(
    PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME),
    attestation=AttestationConveyancePreference.DIRECT,
    verify_origin=lambda origin: origin == ORIGIN,
)

# redis-py connects lazily, so constructing the client here has no side effects
# at import time.
_redis = redis_lib.Redis.from_url(REDIS_URL)


def b64url(data: bytes) -> str:
    """base64url without padding (matches the module's ngx_encode_base64url)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def cose_to_der(key) -> bytes:
    """Convert a COSE public key (python-fido2 CoseKey, a dict of int labels)
    into a DER SubjectPublicKeyInfo, identical to OpenSSL i2d_PUBKEY output."""
    kty = key[1]
    if kty == 2:  # EC2
        curve_cls = _EC_CURVES.get(key[-1])
        if curve_cls is None:
            raise ValueError(f"unsupported EC2 curve: {key[-1]}")
        x = int.from_bytes(bytes(key[-2]), "big")
        y = int.from_bytes(bytes(key[-3]), "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, curve_cls()).public_key()
    elif kty == 3:  # RSA
        n = int.from_bytes(bytes(key[-1]), "big")
        e = int.from_bytes(bytes(key[-2]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
    elif kty == 1:  # OKP (Ed25519)
        if key[-1] != 6:
            raise ValueError(f"unsupported OKP curve: {key[-1]}")
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes(key[-2]))
    else:
        raise ValueError(f"unsupported COSE kty: {kty}")
    return pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def store_credential(user_id: str, auth_data) -> str:
    """Write the verified credential to Redis in the module's schema."""
    cred = auth_data.credential_data
    cid_b64 = b64url(bytes(cred.credential_id))
    der = cose_to_der(cred.public_key)
    alg = cred.public_key[3]

    record = {
        b"user_id": user_id.encode("utf-8"),
        b"public_key": der,
        b"alg": str(alg).encode("ascii"),
        b"sign_count": str(auth_data.counter).encode("ascii"),
        b"created_at": str(int(_now())).encode("ascii"),
        b"last_used_at": b"0",
        b"aaguid": bytes(cred.aaguid),
    }

    key = f"{KEY_PREFIX}cred:{cid_b64}".encode("utf-8")
    index_key = f"{KEY_PREFIX}user:{user_id}:creds".encode("utf-8")
    pipe = _redis.pipeline()
    pipe.hset(key, mapping=record)
    pipe.sadd(index_key, cid_b64)
    pipe.execute()
    return cid_b64


def _now() -> float:
    import time

    return time.time()


def _options_to_json(options) -> dict:
    """Serialize PublicKeyCredentialCreationOptions to WebAuthn-style JSON
    (base64url for byte fields) for navigator.credentials.create()."""
    pk = options.public_key
    return {
        "rp": {"id": pk.rp.id, "name": pk.rp.name},
        "user": {
            "id": b64url(pk.user.id),
            "name": pk.user.name,
            "displayName": pk.user.display_name,
        },
        "challenge": b64url(pk.challenge),
        "pubKeyCredParams": [
            {"type": p.type, "alg": p.alg} for p in pk.pub_key_cred_params
        ],
        # Fido2Server leaves timeout unset (None); send a finite value so the
        # browser does not treat it as "no timeout" (null -> 0 -> waits forever).
        "timeout": pk.timeout or 120000,
        "excludeCredentials": [
            {"type": c.type, "id": b64url(c.id)}
            for c in (pk.exclude_credentials or [])
        ],
        "authenticatorSelection": {
            "residentKey": "required",
            "userVerification": "preferred",
        },
        # pk.attestation is a str-subclass enum; jsonify emits its string value.
        "attestation": pk.attestation,
    }


@app.route("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.route("/register.js")
def register_js():
    return send_from_directory(HERE, "register.js", mimetype="text/javascript")


@app.route("/register/begin", methods=["POST"])
def register_begin():
    body = request.get_json(silent=True) or {}
    user_id = (body.get("user_id") or "").strip()
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=user_id.encode("utf-8"),
            name=user_id,
            display_name=user_id,
        ),
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    session["state"] = state
    session["user_id"] = user_id
    return jsonify(_options_to_json(options))


@app.route("/register/complete", methods=["POST"])
def register_complete():
    state = session.get("state")
    user_id = session.get("user_id")
    if state is None or not user_id:
        return jsonify({"error": "no registration in progress"}), 400

    try:
        auth_data = server.register_complete(state, request.get_json())
        cid_b64 = store_credential(user_id, auth_data)
    except Exception:  # noqa: BLE001 - log details server-side, hide from client
        # Avoid leaking exception details (stack trace internals) to the client.
        app.logger.exception("registration completion failed")
        return jsonify({"ok": False, "error": "registration failed"}), 400
    finally:
        session.pop("state", None)

    return jsonify({"ok": True, "user_id": user_id, "credential_id": cid_b64})


if __name__ == "__main__":
    # Default to localhost so the origin is a secure context for WebAuthn when
    # run standalone. In a container, set WEBAUTHN_BIND_HOST=0.0.0.0 so NGINX can
    # proxy to it (the browser-facing origin stays http://localhost:8080).
    host = os.environ.get("WEBAUTHN_BIND_HOST", "127.0.0.1")
    port = int(os.environ.get("WEBAUTHN_BIND_PORT", "5000"))
    # Debug mode exposes the Werkzeug debugger, which allows arbitrary code
    # execution. Keep it off unless explicitly opted in for local development.
    debug = os.environ.get("WEBAUTHN_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host=host, port=port, debug=debug)
