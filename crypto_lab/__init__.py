"""Lab 02 -- secp256k1, ECDSA, HD wallets and post-quantum cost (student implementation).

All arithmetic is written from scratch on the standard library; pycryptodome is
used for Keccak-256 only.

FOR TEACHING ONLY: not constant-time, not hardened, not audited.
"""

from . import address, ecdsa, hdwallet, pqc  # noqa: F401
from .curve import G, N, P, Point, private_to_public, scalar_mul  # noqa: F401

__version__ = "1.0.0"
