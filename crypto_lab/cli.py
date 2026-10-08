"""Demonstrations for Parts A-D. Every line printed here is computed, not quoted."""

from __future__ import annotations

import hashlib
import secrets
import sys

from . import address, ecdsa, hdwallet, pqc
from .curve import (
    G,
    INFINITY,
    N,
    P,
    add,
    deserialize_public_key,
    double,
    is_on_curve,
    negate,
    private_to_public,
    scalar_mul,
    scalar_mul_ladder,
    serialize_public_key,
)

DEMO_KEY = 0xC0FFEE00BADC0DE1234567890ABCDEF1122334455667788990AABBCCDDEEFF00
TEST_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])


def _title(text: str) -> None:
    print("=" * 78)
    print(text)
    print("=" * 78)


def demo_curve() -> None:
    _title("PART A -- curve arithmetic on secp256k1")
    print(f"p = 0x{P:064x}")
    print(f"n = 0x{N:064x}")
    print(f"G = {G}")
    print(f"G on curve : {is_on_curve(G)}")
    print()
    print("Group law checks:")
    print(f"  n*G is the identity                 : {scalar_mul(N, G).is_infinity}")
    print(f"  (n-1)*G + G is the identity         : {add(scalar_mul(N - 1, G), G).is_infinity}")
    print(f"  G + G == 2*G                        : {add(G, G) == scalar_mul(2, G)}")
    scalars = [secrets.randbelow(N - 1) + 1 for _ in range(20)]
    agree = all(scalar_mul(k, G) == scalar_mul_ladder(k, G) for k in scalars)
    print(f"  double-and-add == Montgomery ladder : {agree}   ({len(scalars)} random scalars)")
    print()
    print("Edge cases:")
    print(f"  G + O == G                          : {add(G, INFINITY) == G}")
    print(f"  G + (-G) is the identity            : {add(G, negate(G)).is_infinity}")
    print(f"  (n-1)*G == -G                       : {scalar_mul(N - 1, G) == negate(G)}")
    print()
    two_g = double(G)
    print("2G:")
    print(f"  x = 0x{two_g.x:064x}")
    print(f"  y = 0x{two_g.y:064x}")
    print()
    compressed = serialize_public_key(G, compressed=True)
    uncompressed = serialize_public_key(G, compressed=False)
    print("SEC1 serialisation of G:")
    print(f"  compressed   ({len(compressed)} B) : {compressed.hex()}")
    print(f"  uncompressed ({len(uncompressed)} B) : {uncompressed.hex()}")
    roundtrip = deserialize_public_key(compressed) == G == deserialize_public_key(uncompressed)
    print(f"  parse(serialise(G)) == G, both forms : {roundtrip}")
    print()


def demo_ecdsa() -> None:
    _title("PART B -- ECDSA and the nonce")
    public_key = private_to_public(DEMO_KEY)
    hash_a = hashlib.sha256(b"Lab 02: pay 1 ETH to Alice").digest()
    hash_b = hashlib.sha256(b"Lab 02: pay 2 ETH to Bob").digest()
    print(f"private key d = 0x{DEMO_KEY:064x}")
    print(f"address       = {address.address_from_private_key(DEMO_KEY)}")
    print()

    signature = ecdsa.sign(DEMO_KEY, hash_a)
    print("Signature with an RFC 6979 nonce:")
    print(f"  r = 0x{signature.r:064x}")
    print(f"  s = 0x{signature.s:064x}")
    print(f"  recovery id = {signature.recovery_id}")
    print(f"  verifies                      : {ecdsa.verify(public_key, hash_a, signature)}")
    print(f"  reproducible across runs      : {ecdsa.sign(DEMO_KEY, hash_a) == signature}")
    print(f"  rejects a different message   : {not ecdsa.verify(public_key, hash_b, signature)}")
    print(f"  low-s enforced (s <= n/2)     : {signature.s <= N // 2}")
    print()

    recovered_key = ecdsa.recover_public_key(hash_a, signature)
    print("Public-key recovery:")
    print(f"  recovered key matches signer  : {recovered_key == public_key}")
    print()

    high_s = ecdsa.Signature(signature.r, N - signature.s, signature.recovery_id ^ 1)
    print("Malleability:")
    print(f"  (r, n-s) also verifies        : {ecdsa.verify(public_key, hash_a, high_s)}")
    print()

    print("Nonce reuse -- two messages signed with the same k:")
    k = ecdsa.rfc6979_nonce(DEMO_KEY, b"\x42" * 32)  # any fixed value; the bug is reusing it
    sig1 = ecdsa.sign(DEMO_KEY, hash_a, nonce=k)
    sig2 = ecdsa.sign(DEMO_KEY, hash_b, nonce=k)
    print(f"  signature 1  r = 0x{sig1.r:064x}")
    print(f"               s = 0x{sig1.s:064x}")
    print(f"  signature 2  r = 0x{sig2.r:064x}")
    print(f"               s = 0x{sig2.s:064x}")
    print(f"  identical r                   : {ecdsa.looks_like_nonce_reuse(sig1, sig2)}")
    recovered = ecdsa.recover_private_key_from_nonce_reuse(sig1.r, sig1.s, hash_a, sig2.s, hash_b)
    print(f"  original d    = 0x{DEMO_KEY:064x}")
    print(f"  recovered d   = 0x{recovered:064x}")
    print(f"  attack succeeded : {recovered == DEMO_KEY}")
    print()

    print("The same attack for every low-s sign combination:")
    raw1 = ecdsa.sign(DEMO_KEY, hash_a, nonce=k, enforce_low_s=False)
    raw2 = ecdsa.sign(DEMO_KEY, hash_b, nonce=k, enforce_low_s=False)
    for label, s1, s2 in (
        ("neither s flipped", raw1.s, raw2.s),
        ("first s flipped  ", N - raw1.s, raw2.s),
        ("second s flipped ", raw1.s, N - raw2.s),
        ("both s flipped   ", N - raw1.s, N - raw2.s),
    ):
        found = ecdsa.recover_private_key_from_nonce_reuse(raw1.r, s1, hash_a, s2, hash_b)
        print(f"  {label}             : {found == DEMO_KEY}")
    print()


def _eth_address(node: hdwallet.ExtendedKey) -> str:
    return address.to_checksum_address(address.public_key_to_address(node.public_point))


def demo_wallet() -> None:
    _title("PART C -- BIP-39 / BIP-32 / BIP-44")
    seed = hdwallet.mnemonic_to_seed(TEST_MNEMONIC)
    root = hdwallet.master_key_from_seed(seed)
    print(f"mnemonic   : {TEST_MNEMONIC}")
    print(f"seed       : {seed.hex()}")
    print(f"master key : 0x{root.key:064x}")
    print(f"chain code : {root.chain_code.hex()}")
    print()

    print("Accounts:")
    for index in range(3):
        node = hdwallet.ethereum_account(TEST_MNEMONIC, index)
        print(f"  {hdwallet.ETHEREUM_PATH}/{index}  ->  {_eth_address(node)}")
    print()

    print("Same mnemonic, different passphrase (address 0):")
    for passphrase in ("", "correct horse", "correct horse "):
        node = hdwallet.ethereum_account(TEST_MNEMONIC, 0, passphrase)
        print(f"  passphrase {passphrase!r:<17} ->  {_eth_address(node)}")
    print()

    account = hdwallet.derive_path(root, hdwallet.ETHEREUM_PATH)
    xpub = account.neuter()
    leaked_child = hdwallet.derive_child(account, 0)
    print(f"Parent-key recovery from the xpub of {hdwallet.ETHEREUM_PATH} and child key /0:")
    print(f"  xpub holds a private key      : {xpub.is_private}")
    recovered = hdwallet.recover_parent_private_key(xpub, leaked_child.key, 0)
    print(f"  recovered parent key          : 0x{recovered:064x}")
    print(f"  matches the real parent : {recovered == account.key}")
    sibling = hdwallet.derive_child(
        hdwallet.ExtendedKey(recovered, xpub.chain_code, xpub.public_point), 1
    )
    print(
        "  sibling /1 key now derivable  : "
        f"{sibling.key == hdwallet.derive_child(account, 1).key}"
    )
    try:
        hdwallet.recover_parent_private_key(
            root.neuter(), hdwallet.derive_child(root, hdwallet.HARDENED_OFFSET).key,
            hdwallet.HARDENED_OFFSET,
        )
        print("  same attack on a hardened child : SUCCEEDED (this would be a bug)")
    except ValueError as error:
        print(f"  same attack on a hardened child : refused -- {error}")
    print()

    print("Watch-only derivation:")
    watch_only = hdwallet.derive_child(xpub, 0)
    print(f"  xpub-derived address matches : {_eth_address(watch_only) == _eth_address(leaked_child)}")
    try:
        hdwallet.derive_child(xpub, hdwallet.HARDENED_OFFSET)
    except ValueError as error:
        print(f"  hardened child from an xpub  : refused -- {error}")
    print()

    print("Addresses:")
    print(f"  keccak256(b'')     = {address.keccak256(b'').hex()}")
    print(f"  sha3_256(b'')      = {hashlib.sha3_256(b'').hexdigest()}   (a different function)")
    for example in (
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ):
        computed = address.to_checksum_address(example.lower())
        print(f"  EIP-55 {computed}  matches the EIP : {computed == example}")
    print()


def demo_pqc() -> None:
    _title("PART D -- post-quantum cost")
    print(pqc.comparison_table())
    print()
    print(pqc.exposure_report())
    print()


DEMOS = {"curve": demo_curve, "ecdsa": demo_ecdsa, "wallet": demo_wallet, "pqc": demo_pqc}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        for demo in DEMOS.values():
            demo()
        return 0
    if len(args) != 1 or args[0] not in DEMOS:
        print(f"usage: python -m crypto_lab [{'|'.join(DEMOS)}]", file=sys.stderr)
        return 2
    DEMOS[args[0]]()
    return 0
