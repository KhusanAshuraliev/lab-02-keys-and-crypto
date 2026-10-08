"""Own tests: the "Done when" conditions of the lab that the course suite does not pin down."""

from __future__ import annotations

import hashlib
import secrets

import pytest

from crypto_lab import address, ecdsa, hdwallet
from crypto_lab.curve import (
    G,
    INFINITY,
    N,
    P,
    Point,
    add,
    deserialize_public_key,
    double,
    inverse_mod,
    is_on_curve,
    negate,
    private_to_public,
    scalar_mul,
    scalar_mul_ladder,
    serialize_public_key,
)

PRIV = 0xC0FFEE00BADC0DE1234567890ABCDEF1122334455667788990AABBCCDDEEFF00
MSG_A = hashlib.sha256(b"message A").digest()
MSG_B = hashlib.sha256(b"message B").digest()
TEST_MNEMONIC = " ".join(["abandon"] * 11 + ["about"])


# --- requirement 1: field and curve arithmetic ----------------------------------


def test_n_minus_one_times_g_plus_g_is_the_identity() -> None:
    assert add(scalar_mul(N - 1, G), G).is_infinity


def test_doubling_a_point_with_y_zero_gives_the_identity() -> None:
    # secp256k1 has no such point (its order is odd); the rule is tested on the function.
    assert double(Point(5, 0)).is_infinity
    assert add(Point(5, 0), Point(5, 0)).is_infinity


def test_ladder_agrees_with_double_and_add_on_many_scalars() -> None:
    scalars = [1, 2, 3, N - 1, N, 2**255, 2**256 - 1]
    scalars += [secrets.randbelow(N - 1) + 1 for _ in range(25)]
    for k in scalars:
        assert scalar_mul(k, G) == scalar_mul_ladder(k, G)


def test_ladder_agrees_on_a_point_other_than_g() -> None:
    base = private_to_public(0xDEADBEEF)
    for _ in range(5):
        k = secrets.randbelow(N - 1) + 1
        assert scalar_mul(k, base) == scalar_mul_ladder(k, base)


def test_scalars_live_modulo_n() -> None:
    k = secrets.randbelow(N - 1) + 1
    assert scalar_mul(k + N, G) == scalar_mul(k, G)
    assert scalar_mul(0, G).is_infinity
    assert scalar_mul(-k, G) == negate(scalar_mul(k, G))


def test_addition_is_commutative_and_associative() -> None:
    a, b, c = (private_to_public(k) for k in (11, 222, 3333))
    assert add(a, b) == add(b, a)
    assert add(add(a, b), c) == add(a, add(b, c))


def test_inverse_mod_works_for_the_group_order_too() -> None:
    for value in (1, 2, 12345, N - 1):
        assert value * inverse_mod(value, N) % N == 1
    with pytest.raises(ZeroDivisionError):
        inverse_mod(N, N)


# --- requirement 2: SEC1 ------------------------------------------------------------


def test_serialisation_of_g_matches_the_published_bytes() -> None:
    compressed = serialize_public_key(G, compressed=True)
    assert compressed.hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    uncompressed = serialize_public_key(G, compressed=False)
    assert len(uncompressed) == 65 and uncompressed[0] == 0x04
    assert deserialize_public_key(compressed) == G == deserialize_public_key(uncompressed)


def test_odd_y_roundtrips_through_the_compressed_form() -> None:
    seen = set()
    for k in range(1, 40):
        point = private_to_public(k)
        encoded = serialize_public_key(point, compressed=True)
        seen.add(encoded[0])
        assert deserialize_public_key(encoded) == point
    assert seen == {0x02, 0x03}


def test_uncompressed_off_curve_point_is_rejected() -> None:
    bad = b"\x04" + G.x.to_bytes(32, "big") + ((G.y + 1) % P).to_bytes(32, "big")
    with pytest.raises(ValueError, match="not on the curve"):
        deserialize_public_key(bad)


@pytest.mark.parametrize("data", [b"", b"\x02" + b"\x01" * 31, b"\x05" + b"\x01" * 32, b"\x04" * 64])
def test_malformed_encodings_are_rejected(data: bytes) -> None:
    with pytest.raises(ValueError):
        deserialize_public_key(data)


def test_identity_cannot_be_serialised() -> None:
    with pytest.raises(ValueError):
        serialize_public_key(INFINITY)


# --- requirement 3: ECDSA -----------------------------------------------------------


def test_rfc6979_published_vector() -> None:
    """Widely used secp256k1/SHA-256 vector: key 1, message 'Satoshi Nakamoto'."""
    digest = hashlib.sha256(b"Satoshi Nakamoto").digest()
    assert ecdsa.rfc6979_nonce(1, digest) == (
        0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
    )
    signature = ecdsa.sign(1, digest)
    assert signature.r == 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8
    assert signature.s == 0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5


def test_recovery_id_is_correct_for_both_s_forms() -> None:
    public_key = private_to_public(PRIV)
    for i in range(12):
        digest = hashlib.sha256(f"rec-{i}".encode()).digest()
        low = ecdsa.sign(PRIV, digest)
        raw = ecdsa.sign(PRIV, digest, enforce_low_s=False)
        assert ecdsa.recover_public_key(digest, low) == public_key
        assert ecdsa.recover_public_key(digest, raw) == public_key
        wrong = ecdsa.Signature(low.r, low.s, low.recovery_id ^ 1)
        assert ecdsa.recover_public_key(digest, wrong) != public_key


def test_verify_rejects_an_off_curve_or_identity_key() -> None:
    signature = ecdsa.sign(PRIV, MSG_A)
    assert not ecdsa.verify(INFINITY, MSG_A, signature)
    assert not ecdsa.verify(Point(G.x, G.y + 1), MSG_A, signature)


def test_der_decodes_back_to_r_and_s() -> None:
    signature = ecdsa.sign(PRIV, MSG_A)
    der = signature.to_der()
    r_len = der[3]
    r = int.from_bytes(der[4 : 4 + r_len], "big")
    assert der[4 + r_len] == 0x02
    s_len = der[5 + r_len]
    s = int.from_bytes(der[6 + r_len : 6 + r_len + s_len], "big")
    assert (r, s) == (signature.r, signature.s)
    assert len(der) == 6 + r_len + s_len


def test_signing_rejects_out_of_range_keys_and_nonces() -> None:
    for bad in (0, N):
        with pytest.raises(ValueError):
            ecdsa.sign(bad, MSG_A)
        with pytest.raises(ValueError):
            ecdsa.sign(PRIV, MSG_A, nonce=bad)


# --- requirement 4: nonce reuse -----------------------------------------------------


@pytest.mark.parametrize(("flip1", "flip2"), [(False, False), (True, False), (False, True), (True, True)])
def test_nonce_reuse_attack_in_all_four_low_s_combinations(flip1: bool, flip2: bool) -> None:
    for _ in range(3):
        k = secrets.randbelow(N - 1) + 1
        sig1 = ecdsa.sign(PRIV, MSG_A, nonce=k, enforce_low_s=False)
        sig2 = ecdsa.sign(PRIV, MSG_B, nonce=k, enforce_low_s=False)
        s1 = N - sig1.s if flip1 else sig1.s
        s2 = N - sig2.s if flip2 else sig2.s
        assert ecdsa.recover_private_key_from_nonce_reuse(sig1.r, s1, MSG_A, s2, MSG_B) == PRIV


def test_nonce_reuse_attack_refuses_unrelated_signatures() -> None:
    sig1 = ecdsa.sign(PRIV, MSG_A)
    sig2 = ecdsa.sign(PRIV, MSG_B)
    with pytest.raises(ValueError):
        ecdsa.recover_private_key_from_nonce_reuse(sig1.r, sig1.s, MSG_A, sig2.s, MSG_B)


# --- requirement 5: BIP-32/39/44 ----------------------------------------------------


def test_zero_passphrase_seed_matches_the_published_vector() -> None:
    assert hdwallet.mnemonic_to_seed(TEST_MNEMONIC).hex().startswith(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    )


def test_bip32_test_vector_1() -> None:
    """BIP-32 test vector 1: seed 000102...0f, chain m/0'/1/2'/2/1000000000."""
    root = hdwallet.master_key_from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    assert root.key == 0xE8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35
    assert root.chain_code.hex() == (
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    )
    child = hdwallet.derive_path(root, "m/0'")
    assert child.key == 0xEDB2E14F9EE77D26DD93B4ECEDE8D16ED408CE149B6CD80B0715A2D911A0AFEA
    leaf = hdwallet.derive_path(root, "m/0'/1/2'/2/1000000000")
    assert leaf.key == 0x471B76E389E528D6DE6D816857E012C5455051CAD6660850E58372A6C3E6E7C8
    assert leaf.depth == 5


def test_published_addresses_for_indices_and_passphrases() -> None:
    def addr(index: int, passphrase: str = "") -> str:
        node = hdwallet.ethereum_account(TEST_MNEMONIC, index, passphrase)
        return address.to_checksum_address(address.public_key_to_address(node.public_point))

    assert addr(1) == "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"
    assert addr(2) == "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"
    assert addr(0, "correct horse") == "0xFf0Bdf99513306994d4aF9949BA7cfA60204D285"
    assert addr(0, "correct horse ") == "0x67dA015b6A80F19822e5d270A7788F72f018a724"


def test_xpub_derivation_gives_the_same_address_and_no_private_key() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    xpub = hdwallet.derive_path(root, "m/44'/60'/0'/0").neuter()
    watch_only = hdwallet.derive_child(xpub, 0)
    assert watch_only.key is None
    assert is_on_curve(watch_only.public_point)
    assert (
        address.to_checksum_address(address.public_key_to_address(watch_only.public_point))
        == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    )


@pytest.mark.parametrize("path", ["44'/60'", "m/x", "m/-1", "m/2147483648", "m//0"])
def test_malformed_paths_are_rejected(path: str) -> None:
    with pytest.raises(ValueError):
        hdwallet.parse_path(path)


def test_unknown_mnemonic_word_is_rejected() -> None:
    wordlist = [f"w{i:04d}" for i in range(2048)]
    words = hdwallet.entropy_to_mnemonic(b"\x22" * 16, wordlist)
    words[0] = "notaword"
    with pytest.raises(ValueError, match="word list"):
        hdwallet.mnemonic_to_entropy(words, wordlist)


@pytest.mark.parametrize("size", [16, 20, 24, 28, 32])
def test_mnemonic_roundtrip_for_every_entropy_size(size: int) -> None:
    wordlist = [f"w{i:04d}" for i in range(2048)]
    entropy = secrets.token_bytes(size)
    assert hdwallet.mnemonic_to_entropy(hdwallet.entropy_to_mnemonic(entropy, wordlist), wordlist) == entropy


# --- requirement 6: parent-key recovery ----------------------------------------------


def test_recovered_parent_key_opens_every_sibling() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    xpub = account.neuter()
    leaked = hdwallet.derive_child(account, 5)

    parent_key = hdwallet.recover_parent_private_key(xpub, leaked.key, 5)
    assert parent_key == account.key
    rebuilt = hdwallet.ExtendedKey(parent_key, xpub.chain_code, xpub.public_point)
    for index in (0, 1, 99):
        assert hdwallet.derive_child(rebuilt, index).key == hdwallet.derive_child(account, index).key


def test_attack_on_a_hardened_child_is_refused_even_with_the_real_child_key() -> None:
    """Asserted behaviour for requirement 6: REFUSED (ValueError), not a wrong key."""
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    hardened_child = hdwallet.derive_child(root, hdwallet.HARDENED_OFFSET + 44)
    with pytest.raises(ValueError, match="immune"):
        hdwallet.recover_parent_private_key(
            root.neuter(), hardened_child.key, hdwallet.HARDENED_OFFSET + 44
        )


def test_normal_child_formula_gives_a_wrong_key_for_a_hardened_child() -> None:
    """Why it is refused: the xpub-computable I_L is not the one a hardened child used."""
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    index = hdwallet.HARDENED_OFFSET
    hardened_child = hdwallet.derive_child(root, index)
    tweak, _ = hdwallet._normal_child_tweak(root.chain_code, root.public_point, index)
    assert (hardened_child.key - tweak) % N != root.key


def test_attack_rejects_a_child_key_from_another_branch() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    with pytest.raises(ValueError):
        hdwallet.recover_parent_private_key(account.neuter(), 12345, 0)


# --- requirement 7: addresses -------------------------------------------------------


def test_demo_key_address() -> None:
    assert address.address_from_private_key(PRIV) == "0xa0f598084F711360A38D861F8Fb2100949170C09"


def test_checksum_accepts_bytes_and_unprefixed_input() -> None:
    expected = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert address.to_checksum_address(bytes.fromhex(expected[2:])) == expected
    assert address.to_checksum_address(expected[2:].upper()) == expected


@pytest.mark.parametrize("bad", ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe", "0x" + "zz" * 20, "hello"])
def test_malformed_addresses_are_not_valid(bad: str) -> None:
    assert not address.is_valid_checksum_address(bad)
