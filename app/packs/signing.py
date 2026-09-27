"""Ed25519 signatures over pack manifests and license files.

Each signed message is prefixed with a fixed domain string, so a signature
made for one purpose (a manifest) can never be replayed as another (a
license). Signature files are small JSON documents:
``{"key_id": "...", "signature": "<base64>"}``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST_DOMAIN = b"skos-pack-manifest-v1\n"
LICENSE_DOMAIN = b"skos-pack-license-v1\n"

MAX_SIGNATURE_FILE_BYTES = 4_096
_KEY_ID = r"^[a-z][a-z0-9-]{1,63}$"


class SignatureError(ValueError):
    """A signature file is malformed or does not verify."""


class UnknownKeyError(SignatureError):
    """The signature names a key that is not in the trust store - treated
    like an unsigned pack (the operator decides), not like a bad signature."""


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    publisher: str
    public_key: bytes  # raw 32-byte Ed25519 public key


@dataclass(frozen=True)
class SignatureFile:
    key_id: str
    signature: bytes


def parse_signature_file(raw: bytes) -> SignatureFile:
    if len(raw) > MAX_SIGNATURE_FILE_BYTES:
        raise SignatureError("signature file is too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SignatureError("signature file is not valid JSON") from None
    if not isinstance(data, dict) or set(data) != {"key_id", "signature"}:
        raise SignatureError("signature file must have exactly 'key_id' and 'signature'")
    key_id, sig = data["key_id"], data["signature"]
    if not isinstance(key_id, str) or not re.fullmatch(_KEY_ID, key_id):
        raise SignatureError("signature file has an invalid key_id")
    if not isinstance(sig, str):
        raise SignatureError("signature must be a base64 string")
    try:
        signature = base64.b64decode(sig, validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError("signature is not valid base64") from None
    if len(signature) != 64:
        raise SignatureError("an Ed25519 signature is 64 bytes")
    return SignatureFile(key_id=key_id, signature=signature)


def verify(
    domain: bytes,
    message: bytes,
    sig: SignatureFile,
    trusted: dict[str, TrustedKey],
    *,
    publisher: str,
) -> TrustedKey:
    """Verify ``sig`` over ``domain + message`` with the trusted key it names,
    which must belong to ``publisher``. Returns that key."""
    key = trusted.get(sig.key_id)
    if key is None:
        raise UnknownKeyError("signed by a key that is not in the trust store")
    if key.publisher != publisher:
        raise SignatureError("the signing key does not belong to the declared publisher")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(sig.signature, domain + message)
    except (InvalidSignature, ValueError):
        raise SignatureError("signature does not verify") from None
    return key


def signature_file_bytes(key_id: str, signature: bytes) -> bytes:
    return (
        json.dumps({"key_id": key_id, "signature": base64.b64encode(signature).decode("ascii")})
        + "\n"
    ).encode("utf-8")
