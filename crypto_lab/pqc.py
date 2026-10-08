"""What replacing ECDSA with a post-quantum signature would cost on chain.

Sizes are the published parameter-set sizes (FIPS 204 ML-DSA, FIPS 205 SLH-DSA,
FN-DSA / Falcon as submitted for FIPS 206). The transaction model is the lab's:
one signed input, one output, 110 bytes of everything that is neither public
key nor signature, a 1 MB block every 10 minutes.
"""

from __future__ import annotations

from dataclasses import dataclass

TX_OVERHEAD_BYTES = 110
BLOCK_BYTES = 1_000_000
BLOCK_INTERVAL_SECONDS = 600


@dataclass(frozen=True)
class Scheme:
    label: str
    quantum_safe: bool
    public_key_bytes: int
    signature_bytes: int
    basis: str


SCHEMES: dict[str, Scheme] = {
    "ecdsa": Scheme("ECDSA (secp256k1)", False, 33, 72, "elliptic-curve discrete log"),
    "schnorr": Scheme("Schnorr (BIP-340)", False, 32, 64, "elliptic-curve discrete log"),
    "ml-dsa-44": Scheme("ML-DSA-44", True, 1312, 2420, "module lattices (FIPS 204)"),
    "ml-dsa-65": Scheme("ML-DSA-65", True, 1952, 3309, "module lattices (FIPS 204)"),
    "slh-dsa-128s": Scheme("SLH-DSA-128s", True, 32, 7856, "hash functions only (FIPS 205)"),
    "fn-dsa-512": Scheme("FN-DSA-512", True, 897, 666, "NTRU lattices (FIPS 206)"),
}


def transaction_bytes(name: str, inputs: int = 1) -> int:
    scheme = SCHEMES[name]
    return TX_OVERHEAD_BYTES + inputs * (scheme.public_key_bytes + scheme.signature_bytes)


def size_multiplier(name: str, inputs: int = 1) -> float:
    """Transaction size relative to the ECDSA transaction of the same shape."""
    return transaction_bytes(name, inputs) / transaction_bytes("ecdsa", inputs)


def throughput_tps(name: str, inputs: int = 1) -> float:
    """Transactions per second if every transaction in a block used this scheme."""
    return BLOCK_BYTES / transaction_bytes(name, inputs) / BLOCK_INTERVAL_SECONDS


def comparison_table(inputs: int = 1) -> str:
    header = f"{'scheme':<20}{'PQ':<5}{'pk (B)':>8}{'sig (B)':>9}{'tx (B)':>8}{'x ECDSA':>10}{'tps':>8}"
    lines = [header, "-" * len(header)]
    for name, scheme in SCHEMES.items():
        lines.append(
            f"{scheme.label:<20}{'yes' if scheme.quantum_safe else 'no':<5}"
            f"{scheme.public_key_bytes:>8}{scheme.signature_bytes:>9}"
            f"{transaction_bytes(name, inputs):>8}"
            f"{size_multiplier(name, inputs):>9.1f}x{throughput_tps(name, inputs):>8.2f}"
        )
    lines.append("")
    lines.append(
        f"model: {inputs} signed input(s), 1 output, {TX_OVERHEAD_BYTES} B overhead, "
        f"{BLOCK_BYTES // 1_000_000} MB block every {BLOCK_INTERVAL_SECONDS // 60} min"
    )
    return "\n".join(lines)


#: category -> (status, why). Shor needs the PUBLIC KEY; a hash of it is not enough.
EXPOSURE: dict[str, tuple[str, str]] = {
    "p2pkh_unspent": (
        "PROTECTED (for now)",
        "The chain holds only HASH160(pubkey). Shor's algorithm solves the discrete log of "
        "a public key and has nothing to work on here; Grover only square-roots a hash "
        "search. Protection ends when the output is spent and the key is revealed.",
    ),
    "p2pk": (
        "EXPOSED",
        "The public key itself is the output script. This covers the earliest coinbase "
        "rewards, which have sat unmoved for over a decade.",
    ),
    "reused_address": (
        "EXPOSED",
        "An earlier spend from the address already published its public key, and funds "
        "still sit behind the same key.",
    ),
    "mempool_transaction": (
        "EXPOSED (briefly)",
        "From broadcast to confirmation the public key is visible while the coin is still "
        "unspent; an attacker who can derive the key within that window can race a "
        "conflicting spend.",
    ),
    "ethereum_any_active": (
        "EXPOSED",
        "Ethereum transactions carry (v, r, s) and the sender is found with ecrecover, so "
        "the public key of every account that has ever sent a transaction can be computed "
        "from chain data. Only never-used receiving accounts are still behind a hash.",
    ),
}


def exposure_report() -> str:
    lines = ["Which coins can a quantum adversary actually attack?", ""]
    for category, (status, reason) in EXPOSURE.items():
        lines.append(f"{category:<22}{status}")
        lines.append(f"{'':<22}{reason}")
        lines.append("")
    lines.append(
        "Harvest Now, Decrypt Later: the ledger is public and permanent, so every exposed "
        "public key can be collected today and attacked whenever the hardware exists. What "
        "decides the migration date is how long the asset must stay secure plus how long "
        "migration takes -- not a forecast of when a quantum computer appears."
    )
    return "\n".join(lines)
