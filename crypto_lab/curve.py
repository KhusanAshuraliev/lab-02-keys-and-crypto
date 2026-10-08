"""secp256k1 from modular arithmetic upward.

The curve is y^2 = x^3 + 7 over the prime field F_p. Points are affine; the
point at infinity (the group identity) is represented by ``Point(None, None)``.

TEACHING CODE. Python integers are arbitrary precision, so no operation here
runs in constant time -- see ``scalar_mul_ladder`` for what that means.
"""

from __future__ import annotations

from dataclasses import dataclass

# Domain parameters (SEC 2, section 2.4.1).
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7


@dataclass(frozen=True)
class Point:
    """An affine point on the curve, or the identity when both fields are None."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point(0x{self.x:064x}, 0x{self.y:064x})"


INFINITY = Point(None, None)
G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def inverse_mod(a: int, m: int = P) -> int:
    """Multiplicative inverse of ``a`` modulo the prime ``m``.

    Fermat's little theorem: a^(m-1) = 1 (mod m) for prime m, hence
    a^(m-2) is the inverse. Both P and N are prime, so this serves the field
    and the scalar group alike. "Division" in every curve formula means this.
    """
    a %= m
    if a == 0:
        raise ZeroDivisionError("0 has no inverse modulo a prime")
    return pow(a, m - 2, m)


def is_on_curve(point: Point) -> bool:
    if point.is_infinity:
        return True
    return (point.y * point.y - point.x * point.x * point.x - A * point.x - B) % P == 0


def negate(point: Point) -> Point:
    if point.is_infinity:
        return point
    return Point(point.x, (-point.y) % P)


def double(point: Point) -> Point:
    """2*point via the tangent line."""
    if point.is_infinity or point.y == 0:
        # A point with y = 0 is its own negation: the tangent is vertical.
        return INFINITY
    slope = (3 * point.x * point.x + A) * inverse_mod(2 * point.y) % P
    x = (slope * slope - 2 * point.x) % P
    y = (slope * (point.x - x) - point.y) % P
    return Point(x, y)


def add(p1: Point, p2: Point) -> Point:
    """p1 + p2 via the chord through both points."""
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    if p1.x == p2.x:
        if (p1.y + p2.y) % P == 0:
            return INFINITY  # p2 == -p1
        return double(p1)  # p2 == p1
    slope = (p2.y - p1.y) * inverse_mod(p2.x - p1.x) % P
    x = (slope * slope - p1.x - p2.x) % P
    y = (slope * (p1.x - x) - p1.y) % P
    return Point(x, y)


def scalar_mul(k: int, point: Point) -> Point:
    """k*point by Double-and-Add, scanning k from the least significant bit.

    O(log k) point operations instead of O(k). NOT constant time: the ``add``
    below runs only for the 1-bits of k, so the running time and power profile
    reveal the Hamming weight -- and, with finer measurement, the bits -- of k.
    """
    if k < 0:
        return scalar_mul(-k, negate(point))
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = add(result, addend)
        addend = double(addend)
        k >>= 1
    return result


def scalar_mul_ladder(k: int, point: Point) -> Point:
    """k*point by the Montgomery ladder.

    Every iteration performs exactly one ``add`` and one ``double`` whatever
    the bit is, and the loop always runs over a fixed 256 bits, so the sequence
    of point operations no longer depends on k. The invariant r1 - r0 == point
    holds throughout.

    This removes the operation-level leak only. Python's big integers, the
    ``if`` on the bit and the identity special cases in ``add`` are still
    data dependent, so this illustrates the technique rather than achieving
    constant time.
    """
    if k < 0:
        return scalar_mul_ladder(-k, negate(point))
    r0, r1 = INFINITY, point
    for i in reversed(range(max(256, k.bit_length()))):
        if (k >> i) & 1:
            r0, r1 = add(r0, r1), double(r1)
        else:
            r0, r1 = double(r0), add(r0, r1)
    return r0


def private_to_public(private_key: int) -> Point:
    """Q = d*G for a private key d in [1, n-1]."""
    if not isinstance(private_key, int) or not 1 <= private_key < N:
        raise ValueError("private key must be an integer in [1, n-1]")
    return scalar_mul(private_key, G)


def lift_x(x: int, odd: bool) -> Point:
    """The curve point with the given x and y parity, or ValueError if none exists."""
    if not 0 <= x < P:
        raise ValueError("x is not a field element")
    rhs = (pow(x, 3, P) + A * x + B) % P
    # p = 3 (mod 4), so a square root of a residue is rhs^((p+1)/4).
    y = pow(rhs, (P + 1) // 4, P)
    if y * y % P != rhs:
        raise ValueError("x does not correspond to a point on the curve")
    if bool(y & 1) != odd:
        y = P - y
    return Point(x, y)


def serialize_public_key(point: Point, compressed: bool = True) -> bytes:
    """SEC1 encoding: 02/03 || x (33 bytes) or 04 || x || y (65 bytes)."""
    if point.is_infinity:
        raise ValueError("the point at infinity has no SEC1 public-key encoding")
    x = point.x.to_bytes(32, "big")
    if compressed:
        return (b"\x03" if point.y & 1 else b"\x02") + x
    return b"\x04" + x + point.y.to_bytes(32, "big")


def deserialize_public_key(data: bytes) -> Point:
    """Parse a SEC1 public key, recovering y from x for the compressed form."""
    if len(data) == 33 and data[0] in (2, 3):
        return lift_x(int.from_bytes(data[1:], "big"), odd=data[0] == 3)
    if len(data) == 65 and data[0] == 4:
        point = Point(int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
        if point.x >= P or point.y >= P or not is_on_curve(point):
            raise ValueError("point is not on the curve")
        return point
    raise ValueError("not a SEC1 public key (expected 33 or 65 bytes with prefix 02/03/04)")
