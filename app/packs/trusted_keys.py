"""Built-in trust store: publisher keys whose signed packs load automatically.

Adding a key (rotation) or removing one (revocation) is a core release. The
matching private keys are never stored in any repository.
"""

from __future__ import annotations

import base64

from app.packs.signing import TrustedKey


def _key(key_id: str, publisher: str, public_key_b64: str) -> TrustedKey:
    raw = base64.b64decode(public_key_b64, validate=True)
    if len(raw) != 32:
        raise ValueError(f"trusted key {key_id!r} is not a 32-byte Ed25519 public key")
    return TrustedKey(key_id=key_id, publisher=publisher, public_key=raw)


_KEYS: tuple[TrustedKey, ...] = (
    _key("kagioneko-2026-01", "kagioneko", "gsVD3a8rLQkjeLfcJpP4M4i01FE3PU5vldpNK4j+0GY="),
)

TRUSTED_KEYS: dict[str, TrustedKey] = {key.key_id: key for key in _KEYS}
