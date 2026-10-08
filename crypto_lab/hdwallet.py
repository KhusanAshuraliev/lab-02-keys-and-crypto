"""BIP-39 seeds, BIP-32 key derivation, BIP-44 paths, and the parent-key
recovery attack on non-hardened children.

Pipeline: mnemonic -> PBKDF2-HMAC-SHA512 -> 512-bit seed -> HMAC-SHA512 master
key + chain code -> child derivation along m/44'/60'/0'/0/i.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass

from .curve import G, N, Point, add, private_to_public, scalar_mul, serialize_public_key

HARDENED_OFFSET = 0x80000000
ETHEREUM_PATH = "m/44'/60'/0'/0"


# --------------------------------------------------------------------------- #
# BIP-39
# --------------------------------------------------------------------------- #


def entropy_to_mnemonic(entropy: bytes, wordlist: Sequence[str]) -> list[str]:
    """Entropy || first ENT/32 bits of SHA-256(entropy), cut into 11-bit word indices."""
    if len(wordlist) != 2048:
        raise ValueError("a BIP-39 word list has exactly 2048 words")
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be 128, 160, 192, 224 or 256 bits")
    checksum_bits = len(entropy) // 4
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    bits = (int.from_bytes(entropy, "big") << checksum_bits) | checksum
    word_count = (len(entropy) * 8 + checksum_bits) // 11
    return [wordlist[(bits >> (11 * i)) & 0x7FF] for i in reversed(range(word_count))]


def mnemonic_to_entropy(words: Sequence[str] | str, wordlist: Sequence[str]) -> bytes:
    """Inverse of ``entropy_to_mnemonic``; rejects unknown words and bad checksums."""
    if isinstance(words, str):
        words = words.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("a mnemonic has 12, 15, 18, 21 or 24 words")
    index = {word: i for i, word in enumerate(wordlist)}
    bits = 0
    for word in words:
        if word not in index:
            raise ValueError(f"word not in the word list: {word!r}")
        bits = (bits << 11) | index[word]
    checksum_bits = len(words) // 3
    entropy = (bits >> checksum_bits).to_bytes(len(words) * 11 // 33 * 4, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if bits & ((1 << checksum_bits) - 1) != expected:
        raise ValueError("mnemonic checksum mismatch")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """PBKDF2-HMAC-SHA512, 2048 rounds, 64 bytes.

    The mnemonic is the PBKDF2 password; the passphrase goes into the SALT
    ("mnemonic" + passphrase). Every passphrase therefore yields a valid seed:
    there is no such thing as a wrong one.
    """
    password = unicodedata.normalize("NFKD", mnemonic).encode("utf-8")
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048, dklen=64)


# --------------------------------------------------------------------------- #
# BIP-32
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExtendedKey:
    """A node of the key tree. ``key`` is None for a public-only (xpub) node."""

    key: int | None
    chain_code: bytes
    public_point: Point
    depth: int = 0
    index: int = 0

    @property
    def is_private(self) -> bool:
        return self.key is not None

    def neuter(self) -> ExtendedKey:
        """The xpub: same public key and chain code, private key removed."""
        return ExtendedKey(None, self.chain_code, self.public_point, self.depth, self.index)


def _split(digest: bytes) -> tuple[int, bytes]:
    return int.from_bytes(digest[:32], "big"), digest[32:]


def master_key_from_seed(seed: bytes) -> ExtendedKey:
    if not 16 <= len(seed) <= 64:
        raise ValueError("seed must be between 128 and 512 bits")
    key, chain_code = _split(hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest())
    if not 1 <= key < N:
        raise ValueError("seed gives an invalid master key; use another seed")
    return ExtendedKey(key, chain_code, private_to_public(key))


def _normal_child_tweak(chain_code: bytes, public_point: Point, index: int) -> tuple[int, bytes]:
    """I_L and the child chain code for a NON-hardened index.

    The inputs are the chain code and the public key -- exactly what an xpub
    contains. That is what makes public derivation possible, and also what
    makes ``recover_parent_private_key`` possible.
    """
    data = serialize_public_key(public_point, compressed=True) + index.to_bytes(4, "big")
    return _split(hmac.new(chain_code, data, hashlib.sha512).digest())


def derive_child(parent: ExtendedKey, index: int) -> ExtendedKey:
    """CKDpriv for a private parent, CKDpub for a public-only one."""
    if not 0 <= index < 2**32:
        raise ValueError("child index must fit in 32 bits")

    if index >= HARDENED_OFFSET:
        if not parent.is_private:
            raise ValueError("hardened derivation requires the parent private key")
        data = b"\x00" + parent.key.to_bytes(32, "big") + index.to_bytes(4, "big")
        tweak, chain_code = _split(hmac.new(parent.chain_code, data, hashlib.sha512).digest())
    else:
        tweak, chain_code = _normal_child_tweak(parent.chain_code, parent.public_point, index)

    if tweak >= N:
        raise ValueError("invalid child (I_L >= n); use the next index")

    if parent.is_private:
        key = (tweak + parent.key) % N
        if key == 0:
            raise ValueError("invalid child (key is zero); use the next index")
        return ExtendedKey(key, chain_code, private_to_public(key), parent.depth + 1, index)

    point = add(scalar_mul(tweak, G), parent.public_point)
    if point.is_infinity:
        raise ValueError("invalid child (point at infinity); use the next index")
    return ExtendedKey(None, chain_code, point, parent.depth + 1, index)


def parse_path(path: str) -> list[int]:
    """"m/44'/60'/0'/0/0" -> list of indices, with the hardened offset applied."""
    parts = path.strip().split("/")
    if parts[0] not in ("m", "M"):
        raise ValueError("a derivation path starts with 'm'")
    indices = []
    for part in parts[1:]:
        hardened = part[-1:] in ("'", "h", "H")
        number = part[:-1] if hardened else part
        if not number.isdecimal() or int(number) >= HARDENED_OFFSET:
            raise ValueError(f"invalid path component: {part!r}")
        indices.append(int(number) + (HARDENED_OFFSET if hardened else 0))
    return indices


def format_path(indices: Sequence[int]) -> str:
    return "/".join(
        ["m"]
        + [f"{i - HARDENED_OFFSET}'" if i >= HARDENED_OFFSET else str(i) for i in indices]
    )


def derive_path(root: ExtendedKey, path: str | Sequence[int]) -> ExtendedKey:
    node = root
    for index in parse_path(path) if isinstance(path, str) else path:
        node = derive_child(node, index)
    return node


def ethereum_account(mnemonic: str, index: int = 0, passphrase: str = "") -> ExtendedKey:
    """The BIP-44 Ethereum key m/44'/60'/0'/0/index (MetaMask's convention)."""
    root = master_key_from_seed(mnemonic_to_seed(mnemonic, passphrase))
    return derive_path(root, f"{ETHEREUM_PATH}/{index}")


# --------------------------------------------------------------------------- #
# The attack
# --------------------------------------------------------------------------- #


def recover_parent_private_key(parent_xpub: ExtendedKey, child_key: int, index: int) -> int:
    """Parent private key from the parent XPUB and one non-hardened child private key.

    child = (I_L + parent) mod n, and for a normal child I_L is computed from
    the chain code and the parent PUBLIC key, both in the xpub. So

        parent = (child - I_L) mod n.

    For a hardened child I_L = HMAC(chain code, 0x00 || parent PRIVATE key || i):
    the attacker would need the very key being sought, so the attempt is refused.
    """
    if index >= HARDENED_OFFSET:
        raise ValueError(
            "hardened children are immune: I_L depends on the parent private key"
        )
    tweak, _ = _normal_child_tweak(parent_xpub.chain_code, parent_xpub.public_point, index)
    parent_key = (child_key - tweak) % N
    if parent_key == 0 or scalar_mul(parent_key, G) != parent_xpub.public_point:
        raise ValueError("this child key does not belong to this xpub at this index")
    return parent_key
