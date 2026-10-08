"""ECDSA over secp256k1: sign, verify, RFC 6979 nonces, low-s, key recovery,
and the nonce-reuse attack.

Notation follows the lab: d private key, Q = d*G public key, z message hash as
an integer, k nonce, R = k*G, r = R.x mod n, s = k^-1 (z + r*d) mod n.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterator
from dataclasses import dataclass

from .curve import G, N, P, Point, add, inverse_mod, is_on_curve, lift_x, negate, scalar_mul

HALF_N = N // 2


@dataclass(frozen=True)
class Signature:
    """(r, s) plus the recovery id: bit 0 = parity of R.y, bit 1 = R.x overflowed n."""

    r: int
    s: int
    recovery_id: int = 0

    def to_bytes(self) -> bytes:
        """Compact 64-byte form r || s."""
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big")

    def to_der(self) -> bytes:
        """ASN.1 DER: SEQUENCE { INTEGER r, INTEGER s }."""

        def integer(value: int) -> bytes:
            body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            if body[0] & 0x80:  # keep it positive
                body = b"\x00" + body
            return b"\x02" + bytes([len(body)]) + body

        body = integer(self.r) + integer(self.s)
        return b"\x30" + bytes([len(body)]) + body


def _hash_to_int(message_hash: bytes) -> int:
    if not isinstance(message_hash, bytes | bytearray) or len(message_hash) != 32:
        raise ValueError("message hash must be exactly 32 bytes")
    return int.from_bytes(message_hash, "big")


def _rfc6979_candidates(private_key: int, message_hash: bytes) -> Iterator[int]:
    """The HMAC-DRBG of RFC 6979 section 3.2 with SHA-256, yielding nonce candidates."""
    key_octets = private_key.to_bytes(32, "big")
    # bits2octets: the hash reduced mod n, so equal z always feed the DRBG equally.
    hash_octets = (_hash_to_int(message_hash) % N).to_bytes(32, "big")

    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + key_octets + hash_octets, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + key_octets + hash_octets, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            yield candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def rfc6979_nonce(private_key: int, message_hash: bytes) -> int:
    """Deterministic nonce k in [1, n-1], a function of the key and the hash only."""
    if not 1 <= private_key < N:
        raise ValueError("private key must be in [1, n-1]")
    return next(_rfc6979_candidates(private_key, message_hash))


def _sign_with_nonce(private_key: int, z: int, k: int) -> Signature | None:
    point = scalar_mul(k, G)
    r = point.x % N
    if r == 0:
        return None
    s = inverse_mod(k, N) * (z + r * private_key) % N
    if s == 0:
        return None
    return Signature(r, s, (point.y & 1) | (2 if point.x >= N else 0))


def sign(
    private_key: int,
    message_hash: bytes,
    nonce: int | None = None,
    enforce_low_s: bool = True,
) -> Signature:
    """Sign a 32-byte hash.

    ``nonce`` exists only so the reuse attack can be demonstrated; leaving it
    None uses RFC 6979. With ``enforce_low_s`` the signature is normalised to
    s <= n/2, which flips the parity bit of the recovery id.
    """
    if not 1 <= private_key < N:
        raise ValueError("private key must be in [1, n-1]")
    z = _hash_to_int(message_hash)

    if nonce is not None:
        if not 1 <= nonce < N:
            raise ValueError("nonce must be in [1, n-1]")
        signature = _sign_with_nonce(private_key, z, nonce)
        if signature is None:
            raise ValueError("this nonce gives r = 0 or s = 0; choose another")
    else:
        signature = None
        for k in _rfc6979_candidates(private_key, message_hash):
            signature = _sign_with_nonce(private_key, z, k)
            if signature is not None:
                break

    if enforce_low_s and signature.s > HALF_N:
        # (r, n-s) is the signature made with -k, whose R has the opposite y parity.
        signature = Signature(signature.r, N - signature.s, signature.recovery_id ^ 1)
    return signature


def verify(public_key: Point, message_hash: bytes, signature: Signature) -> bool:
    """True iff the signature is valid for this key and hash."""
    r, s = signature.r, signature.s
    if not (1 <= r < N and 1 <= s < N):
        return False
    if public_key.is_infinity or not is_on_curve(public_key):
        return False
    z = _hash_to_int(message_hash)
    w = inverse_mod(s, N)
    point = add(scalar_mul(z * w % N, G), scalar_mul(r * w % N, public_key))
    return not point.is_infinity and point.x % N == r


def recover_public_key(message_hash: bytes, signature: Signature) -> Point:
    """Reconstruct Q from a signature: Q = r^-1 (s*R - z*G). Ethereum's ecrecover."""
    r, s, rec = signature.r, signature.s, signature.recovery_id
    if not (1 <= r < N and 1 <= s < N) or not 0 <= rec <= 3:
        raise ValueError("signature values out of range")
    x = r + (N if rec & 2 else 0)
    if x >= P:
        raise ValueError("recovery id does not match this signature")
    big_r = lift_x(x, odd=bool(rec & 1))
    z = _hash_to_int(message_hash)
    r_inv = inverse_mod(r, N)
    public_key = scalar_mul(
        r_inv, add(scalar_mul(s, big_r), negate(scalar_mul(z % N, G)))
    )
    if public_key.is_infinity:
        raise ValueError("signature does not determine a public key")
    return public_key


def looks_like_nonce_reuse(sig1: Signature, sig2: Signature) -> bool:
    """Equal k means equal R, hence equal r: reuse is visible without any secret."""
    return sig1.r == sig2.r and sig1.s != sig2.s


def recover_private_key_from_nonce_reuse(
    r: int, s1: int, hash1: bytes, s2: int, hash2: bytes
) -> int:
    """Recover d from two signatures that share a nonce.

    From s1 = k^-1 (z1 + r d) and s2 = k^-1 (z2 + r d):

        k = (z1 - z2) / (s1 - s2)        d = (s1 k - z1) / r        (mod n)

    Low-s normalisation may have replaced either s by n - s independently
    (equivalent to signing with -k). Flipping both signs only negates k and
    leaves d unchanged, so two cases remain: the signs agree (use s1 - s2) or
    they differ (use s1 + s2). The right one is the candidate whose public key
    verifies both signatures.
    """
    z1, z2 = _hash_to_int(hash1), _hash_to_int(hash2)
    if (z1 - z2) % N == 0:
        raise ValueError("the two messages are identical: nothing can be recovered")
    r_inv = inverse_mod(r, N)
    for s2_signed in (s2, N - s2):
        denominator = (s1 - s2_signed) % N
        if denominator == 0:
            continue
        k = (z1 - z2) * inverse_mod(denominator, N) % N
        d = (s1 * k - z1) * r_inv % N
        if d == 0:
            continue
        public_key = scalar_mul(d, G)
        if verify(public_key, hash1, Signature(r, s1)) and verify(
            public_key, hash2, Signature(r, s2)
        ):
            return d
    raise ValueError("these signatures do not share a nonce")
