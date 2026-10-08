"""Ethereum addresses and the EIP-55 mixed-case checksum."""

from __future__ import annotations

from Crypto.Hash import keccak

from .curve import Point, private_to_public


def keccak256(data: bytes) -> bytes:
    """Keccak-256 as used by Ethereum.

    NOT hashlib.sha3_256: the standardised SHA-3 changed the padding byte, so
    the two functions give unrelated digests for the same input.
    """
    return keccak.new(digest_bits=256, data=data).digest()


def public_key_to_address(public_key: Point) -> str:
    """Last 20 bytes of Keccak-256 over the 64-byte x || y (no 04 prefix)."""
    if public_key.is_infinity:
        raise ValueError("the point at infinity is not a public key")
    raw = public_key.x.to_bytes(32, "big") + public_key.y.to_bytes(32, "big")
    return "0x" + keccak256(raw)[-20:].hex()


def _hex_body(address: str | bytes) -> str:
    """The 40 lowercase hex digits of an address, or ValueError."""
    if isinstance(address, bytes | bytearray):
        address = bytes(address).hex()
    body = address[2:] if address[:2] in ("0x", "0X") else address
    if len(body) != 40:
        raise ValueError("an Ethereum address is 20 bytes (40 hex digits)")
    try:
        int(body, 16)
    except ValueError:
        raise ValueError("address contains non-hex characters") from None
    return body.lower()


def to_checksum_address(address: str | bytes) -> str:
    """EIP-55: uppercase hex letter i when nibble i of the hash is >= 8.

    The hash is taken over the lowercase hex STRING (ASCII), not the 20 bytes.
    """
    body = _hex_body(address)
    digest = keccak256(body.encode("ascii")).hex()
    return "0x" + "".join(
        char.upper() if int(nibble, 16) >= 8 else char
        for char, nibble in zip(body, digest, strict=False)
    )


def is_valid_checksum_address(address: str) -> bool:
    """True for a correct EIP-55 address, or an all-lower/all-upper (unchecked) one."""
    try:
        body = _hex_body(address)
    except ValueError:
        return False
    given = address[2:] if address[:2] in ("0x", "0X") else address
    if given in (body, body.upper()):
        return True  # no case information: valid but unchecked
    return "0x" + given == to_checksum_address(body)


def address_from_private_key(private_key: int) -> str:
    return to_checksum_address(public_key_to_address(private_to_public(private_key)))
