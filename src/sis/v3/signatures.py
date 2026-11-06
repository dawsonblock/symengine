"""Ed25519 signatures (RFC 8032) for v3 outcome receipts.

When the optional ``cryptography`` package is installed it is used — a
vetted, constant-time backend. Otherwise a compact pure-Python RFC 8032
implementation provides the same wire-compatible signature scheme; it is
validated against the RFC test vectors and cross-checked against the
``cryptography`` backend in the test suite, but its scalar arithmetic is
not constant-time. ``backend()`` reports which implementation is active so
receipts and reports can state it honestly.
"""
from __future__ import annotations

import hashlib
import os

try:  # preferred constant-time backend
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Ed25519PrivateKey,
        Ed25519PublicKey as _Ed25519PublicKey,
    )
    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - depends on environment
    _HAS_CRYPTOGRAPHY = False

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
# Extended twisted Edwards coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z.
_B = (_BX % _Q, _BY, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _add(P: tuple[int, int, int, int], Q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Hisil-Wong-Carter-Dawson extended addition for a = -1."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = x1 * x2 % _Q
    b = y1 * y2 % _Q
    c = _D * t1 * t2 % _Q
    d = z1 * z2 % _Q
    e = ((x1 + y1) * (x2 + y2) - a - b) % _Q
    f = (d - c) % _Q
    g = (d + c) % _Q
    h = (b + a) % _Q
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _scalarmult(P: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    result = _IDENTITY
    addend = P
    while e > 0:
        if e & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        e >>= 1
    return result


def _to_affine(P: tuple[int, int, int, int]) -> tuple[int, int]:
    z_inv = pow(P[2], _Q - 2, _Q)
    return (P[0] * z_inv % _Q, P[1] * z_inv % _Q)


def _encode_int(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encode_point(P: tuple[int, int, int, int]) -> bytes:
    x, y = _to_affine(P)
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_int(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _decode_point(data: bytes) -> tuple[int, int]:
    if len(data) != 32:
        raise ValueError("point encoding must be 32 bytes")
    y = _decode_int(data) & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("point y coordinate out of range")
    x = _xrecover(y)
    if (x & 1) != ((data[31] >> 7) & 1):
        x = _Q - x
    if (-x * x + y * y - 1 - _D * x * x % _Q * y * y) % _Q != 0:
        raise ValueError("point is not on the curve")
    return (x, y)


def _clamped_scalar(digest: bytes) -> int:
    value = _decode_int(digest[:32])
    value &= (1 << 254) - 8
    value |= 1 << 254
    return value


def _py_public_key(seed: bytes) -> bytes:
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a = _clamped_scalar(_sha512(seed))
    return _encode_point(_scalarmult(_B, a))


def _py_sign(seed: bytes, message: bytes) -> bytes:
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    digest = _sha512(seed)
    a = _clamped_scalar(digest)
    public = _encode_point(_scalarmult(_B, a))
    r = _decode_int(_sha512(digest[32:64] + message)) % _L
    encoded_r = _encode_point(_scalarmult(_B, r))
    s = (r + _decode_int(_sha512(encoded_r + public + message)) * a) % _L
    return encoded_r + _encode_int(s)


def _py_verify(signature: bytes, message: bytes, public: bytes) -> bool:
    if not (isinstance(signature, bytes) and isinstance(message, bytes) and isinstance(public, bytes)):
        return False
    if len(signature) != 64 or len(public) != 32:
        return False
    s = _decode_int(signature[32:])
    if s >= _L:
        return False
    try:
        r_x, r_y = _decode_point(signature[:32])
        a_x, a_y = _decode_point(public)
    except ValueError:
        return False
    h = _decode_int(_sha512(signature[:32] + public + message)) % _L
    left = _to_affine(_scalarmult(_B, s))
    right_point = (r_x, r_y, 1, r_x * r_y % _Q)
    a_point = (a_x, a_y, 1, a_x * a_y % _Q)
    right = _to_affine(_add(right_point, _scalarmult(a_point, h)))
    return left == right


def backend() -> str:
    """Name the active signing backend for honest reporting."""
    return "cryptography" if _HAS_CRYPTOGRAPHY else "vendored-python"


def public_key(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key for a 32-byte secret seed."""
    if not _HAS_CRYPTOGRAPHY:
        return _py_public_key(seed)
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        _serialization.Encoding.Raw, _serialization.PublicFormat.Raw
    )


def sign(seed: bytes, message: bytes) -> bytes:
    """Return the 64-byte deterministic Ed25519 signature over ``message``."""
    if not _HAS_CRYPTOGRAPHY:
        return _py_sign(seed, message)
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def verify(signature: bytes, message: bytes, public: bytes) -> bool:
    """Check an Ed25519 signature; malformed inputs return False."""
    if not _HAS_CRYPTOGRAPHY:
        return _py_verify(signature, message, public)
    if not (isinstance(signature, bytes) and isinstance(message, bytes) and isinstance(public, bytes)):
        return False
    if len(signature) != 64 or len(public) != 32:
        return False
    try:
        _Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (_InvalidSignature, ValueError):
        return False
    return True


def generate_keypair() -> tuple[bytes, bytes]:
    """Return ``(secret_seed, public_key)`` from OS randomness."""
    seed = os.urandom(32)
    return seed, public_key(seed)
