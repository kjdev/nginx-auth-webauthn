#!/usr/bin/env python3
"""WebAuthn test-vector generator for the Test::Nginx integration suite.

The integration tests need real, cryptographically valid WebAuthn ceremonies,
but the challenge is issued dynamically by the running module (shm, single-use),
so static fixtures cannot pass ``challenge_consume``. This tool generates the
material at test time:

    keygen       -> a fresh ES256 (P-256) keypair + random credential id
    attestation  -> an AttestationResponse JSON for ``auth-webauthn-admin
                    register`` (seeds Redis, exercises the CLI)
    assertion    -> a ``POST /webauthn/verify`` request body, signed over a
                    challenge fetched from the live server

Only ES256 is supported (matches the integration-test scope). The single
dependency is ``cryptography``; a minimal CBOR encoder is bundled so neither
``cbor2`` nor ``fido2`` is required.
"""

import argparse
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

# COSE / WebAuthn constants for ES256.
COSE_ALG_ES256 = -7
COSE_KTY_EC2 = 2
COSE_CRV_P256 = 1

# authenticatorData flag bits (WebAuthn 6.1).
FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified
FLAG_AT = 0x40  # attested credential data included


def b64url(data: bytes) -> str:
    """base64url without padding (matches ngx_encode_base64url output)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# --- minimal CBOR encoder (definite-length, the subset WebAuthn needs) ------

def _cbor_head(major: int, n: int) -> bytes:
    mt = major << 5
    if n < 24:
        return bytes([mt | n])
    if n < 0x100:
        return bytes([mt | 24, n])
    if n < 0x10000:
        return bytes([mt | 25, n >> 8, n & 0xFF])
    if n < 0x100000000:
        return bytes([mt | 26, (n >> 24) & 0xFF, (n >> 16) & 0xFF,
                      (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError("integer too large for this encoder")


def cbor(obj) -> bytes:
    """Encode ints, byte strings, text strings, and dicts (insertion order)."""
    if isinstance(obj, bool):
        raise TypeError("bool is not encodable here")
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_head(0, obj)
        return _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        data = obj.encode("utf-8")
        return _cbor_head(3, len(data)) + data
    if isinstance(obj, dict):
        out = _cbor_head(5, len(obj))
        for key, value in obj.items():
            out += cbor(key) + cbor(value)
        return out
    raise TypeError(f"unsupported CBOR type: {type(obj)!r}")


# --- key handling -----------------------------------------------------------

def load_key(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise SystemExit("error: key is not an EC private key")
    return key


def cose_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    """COSE_Key (CBOR) for the public key, as embedded in attestation."""
    numbers = key.public_key().public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    # Insertion order mirrors what browsers/python-fido2 emit.
    return cbor({
        1: COSE_KTY_EC2,
        3: COSE_ALG_ES256,
        -1: COSE_CRV_P256,
        -2: x,
        -3: y,
    })


def rp_id_hash(rp_id: str) -> bytes:
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


def auth_data(rp_id: str, flags: int, sign_count: int,
              cred_id: bytes = b"", cose: bytes = b"") -> bytes:
    """Assemble authenticatorData (WebAuthn 6.1)."""
    data = rp_id_hash(rp_id)
    data += bytes([flags])
    data += sign_count.to_bytes(4, "big")
    if flags & FLAG_AT:
        data += b"\x00" * 16                       # aaguid
        data += len(cred_id).to_bytes(2, "big")    # credentialIdLength
        data += cred_id
        data += cose
    return data


def client_data_json(ceremony_type: str, challenge_b64: str,
                     origin: str) -> bytes:
    """Serialize clientDataJSON. challenge is kept verbatim as base64url so the
    module can decode it and match the single-use shm entry."""
    obj = {
        "type": ceremony_type,
        "challenge": challenge_b64,
        "origin": origin,
        "crossOrigin": False,
    }
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


# --- subcommands ------------------------------------------------------------

def cmd_keygen(args) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(args.out, "wb") as fh:
        fh.write(pem)
    cred_id = os.urandom(16)
    # stdout: the credential id (base64url) the caller threads into attestation
    # and assertion, and which becomes the Redis key.
    sys.stdout.write(b64url(cred_id) + "\n")


def cmd_attestation(args) -> None:
    key = load_key(args.key)
    cred_id = b64url_decode(args.cid)
    cdj = client_data_json("webauthn.create", b64url(os.urandom(32)),
                           args.origin)
    ad = auth_data(args.rp_id, FLAG_UP | FLAG_UV | FLAG_AT, 0,
                   cred_id, cose_key(key))
    attestation_object = cbor({
        "fmt": "none",
        "attStmt": {},
        "authData": ad,
    })
    response = {
        "id": args.cid,
        "rawId": args.cid,
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url(cdj),
            "attestationObject": b64url(attestation_object),
        },
        "clientExtensionResults": {},
    }
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")


def cmd_assertion(args) -> None:
    key = load_key(args.key)
    origin = "https://evil.example" if args.bad_origin else args.origin
    rp_id = "attacker.example" if args.bad_rpid else args.rp_id

    cdj = client_data_json(args.type, args.challenge, origin)
    ad = auth_data(rp_id, FLAG_UP | FLAG_UV, args.sign_count)

    signed = ad + hashlib.sha256(cdj).digest()
    signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    if args.tamper_sig:
        # Re-encode with a perturbed r so the DER stays well-formed but the
        # signature no longer verifies.
        r, s = decode_dss_signature(signature)
        signature = encode_dss_signature(r ^ 1, s)

    body = {
        "id": args.cid,
        "rawId": args.cid,
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url(cdj),
            "authenticatorData": b64url(ad),
            "signature": b64url(signature),
            "userHandle": None,
        },
        "clientExtensionResults": {},
    }
    json.dump(body, sys.stdout)
    sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an ES256 key + credential id")
    p.add_argument("--out", required=True, help="output PEM path")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("attestation", help="emit AttestationResponse JSON")
    p.add_argument("--key", required=True)
    p.add_argument("--cid", required=True, help="credential id (base64url)")
    p.add_argument("--rp-id", required=True)
    p.add_argument("--origin", required=True)
    p.set_defaults(func=cmd_attestation)

    p = sub.add_parser("assertion", help="emit a /webauthn/verify request body")
    p.add_argument("--key", required=True)
    p.add_argument("--cid", required=True, help="credential id (base64url)")
    p.add_argument("--rp-id", required=True)
    p.add_argument("--origin", required=True)
    p.add_argument("--challenge", required=True,
                   help="base64url challenge from /webauthn/challenge")
    p.add_argument("--sign-count", type=int, default=1)
    p.add_argument("--type", default="webauthn.get",
                   help="clientData type (override for negative tests)")
    p.add_argument("--bad-origin", action="store_true")
    p.add_argument("--bad-rpid", action="store_true")
    p.add_argument("--tamper-sig", action="store_true")
    p.set_defaults(func=cmd_assertion)

    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
