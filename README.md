# lab-02-keys-and-crypto — Lab 02 student implementation

secp256k1, ECDSA, HD wallets and post-quantum cost, written for **OE Blockchain, Lab 02 (Elliptic curves, ECDSA, HD wallets and post-quantum cost)**.

All arithmetic is implemented from scratch on the Python standard library. The only dependency is `pycryptodome`, used for Keccak-256 alone. No `ecdsa`, `coincurve`, `eth-keys` or `bip_utils`.

> **For teaching only.** Nothing here is constant-time, hardened or audited. Never use it to protect anything of value.

## Report

- [Lab 02 report (PDF)](report/Lab02_Report_Khusan_Ashuraliev.pdf)
- [`evidence/`](evidence/) — demo output for Parts A–D and both test runs

## Usage

```bash
uv sync
uv run pytest                      # 113 passed
uv run python -m crypto_lab        # all four parts
uv run python -m crypto_lab curve  # Part A   (also: ecdsa, wallet, pqc)
```

## Requirements coverage

| # | Requirement | Where | Tests |
|---|---|---|---|
| 1 | Field and curve arithmetic, Double-and-Add, constant-time variant | `curve.py` → `inverse_mod`, `add`, `double`, `scalar_mul`, `scalar_mul_ladder` | published `2G`; `n·G = O`, `(n−1)·G + G = O`; `P + O`, `P + (−P)`, doubling at `y = 0`; ladder vs Double-and-Add on 30+ scalars |
| 2 | SEC1 serialisation | `curve.py` → `serialize_public_key`, `deserialize_public_key`, `lift_x` | compressed `G` = `0279be66…16f81798`; round trip in both forms; off-curve and malformed input rejected |
| 3 | ECDSA: sign, verify, RFC 6979, low-s, recovery | `ecdsa.py` | deterministic signatures; published RFC 6979 vector (key 1, "Satoshi Nakamoto"); `s ≤ n/2`; recovery id correct for both `s` forms |
| 4 | Nonce-reuse attack | `ecdsa.py` → `recover_private_key_from_nonce_reuse` | exact `d` in all four low-s sign combinations |
| 5 | BIP-32/39/44 | `hdwallet.py` | BIP-39 seed vectors; BIP-32 test vector 1; `m/44'/60'/0'/0/0` = `0x9858EfFD…EcaEda94`; xpub derivation; hardened index from an xpub raises |
| 6 | Parent-key recovery attack | `hdwallet.py` → `recover_parent_private_key` | exact parent key from xpub + one normal child; hardened child is **refused** (`ValueError`), and the test asserts that |
| 7 | Ethereum addresses, EIP-55 | `address.py` | four EIP-55 examples; Keccak-256 of the empty string, asserted different from `hashlib.sha3_256` |

`tests/test_crypto.py` is the course's reference suite (64 tests), copied **unchanged**.
`tests/test_extra.py` adds 49 further tests for the conditions above that the course suite does not pin down.

## Layout

| File | Responsibility |
|---|---|
| `crypto_lab/curve.py` | field inverse, point addition and doubling, both scalar multiplications, SEC1 |
| `crypto_lab/ecdsa.py` | RFC 6979, sign, verify, DER/compact encoding, public-key recovery, nonce-reuse attack |
| `crypto_lab/hdwallet.py` | BIP-39 mnemonic/seed, BIP-32 private and public derivation, BIP-44 paths, parent-key recovery |
| `crypto_lab/address.py` | Keccak-256, Ethereum address, EIP-55 |
| `crypto_lab/pqc.py` | signature-size and throughput comparison, exposure classification |
| `crypto_lab/cli.py` | the Part A–D demonstrations |

## Design notes

- **Division is inversion.** Every division in the curve formulas is `inverse_mod` (Fermat, `a^(m-2) mod m`), used with `p` for coordinates and with `n` for scalars.
- **Scalars are not reduced before multiplying.** `scalar_mul(n, G)` runs the full Double-and-Add and reaches the identity because the arithmetic is right, not because of a shortcut.
- **Low-s and the recovery id.** Replacing `s` by `n − s` corresponds to signing with `−k`, so the parity bit of the recovery id is flipped at the same time.
- **Nonce-reuse recovery needs no public key.** Flipping both `s` values only negates `k`, so two candidates remain (`s1 − s2` and `s1 + s2`); the one whose derived public key verifies both signatures is returned.
- **Known weakness.** `scalar_mul` branches on the bits of the scalar, and Python big-integer arithmetic is not constant-time even inside the ladder. See the implementation-risk section of the report.
