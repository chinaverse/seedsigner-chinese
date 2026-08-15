"""
Regression coverage for the RFC 6979 audit in docs/rfc6979_deterministic_nonce_explained.md.

Independently reimplements RFC 6979 section 3.2 (HMAC-SHA256 DRBG) from the spec text -
not by importing embit's own deterministic_k() - and an independent secp256k1 point
multiplication, then cross-checks both against the actual production signing call paths
(psbt signing via ec.PrivateKey.sign(), and message signing via embit_utils.sign_message()).
The goal is to keep proving, on every run, that no code path ever supplies external
randomness to the ECDSA nonce and that distinct messages never collide on the same nonce.
"""
import hashlib
import hmac as hmac_mod

from embit import ec
from embit.util import key as embit_key

from seedsigner.helpers import embit_utils


SECP256K1_ORDER = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
SECP256K1_P = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
SECP256K1_GX = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
SECP256K1_GY = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8

TEST_SECRET_INT = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F672


def independent_rfc6979_k(secret_int: int, z_int: int) -> int:
    """RFC 6979 section 3.2 (steps b-h), from the spec text, independent of embit."""
    x = secret_int.to_bytes(32, "big")
    if z_int >= SECP256K1_ORDER:
        z_int -= SECP256K1_ORDER
    h1 = z_int.to_bytes(32, "big")

    V = b"\x01" * 32
    K = b"\x00" * 32
    K = hmac_mod.new(K, V + b"\x00" + x + h1, hashlib.sha256).digest()
    V = hmac_mod.new(K, V, hashlib.sha256).digest()
    K = hmac_mod.new(K, V + b"\x01" + x + h1, hashlib.sha256).digest()
    V = hmac_mod.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac_mod.new(K, V, hashlib.sha256).digest()
        candidate = int.from_bytes(V, "big")
        if 1 <= candidate < SECP256K1_ORDER:
            return candidate
        K = hmac_mod.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac_mod.new(K, V, hashlib.sha256).digest()


def _ec_point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return None
    if p1 == p2:
        m = (3 * x1 * x1) * pow(2 * y1, SECP256K1_P - 2, SECP256K1_P) % SECP256K1_P
    else:
        m = (y2 - y1) * pow(x2 - x1, SECP256K1_P - 2, SECP256K1_P) % SECP256K1_P
    x3 = (m * m - x1 - x2) % SECP256K1_P
    y3 = (m * (x1 - x3) - y1) % SECP256K1_P
    return (x3, y3)


def _r_from_k(k: int) -> int:
    """Independent scalar multiplication k*G -> r = x mod n, without embit."""
    result = None
    addend = (SECP256K1_GX, SECP256K1_GY)
    while k:
        if k & 1:
            result = _ec_point_add(result, addend)
        addend = _ec_point_add(addend, addend)
        k >>= 1
    return result[0] % SECP256K1_ORDER


def _der_extract_r(der: bytes) -> int:
    rlen = der[3]
    return int.from_bytes(der[4:4 + rlen], "big")


def test_embit_deterministic_k_matches_independent_rfc6979_reference():
    z1 = int.from_bytes(hashlib.sha256(b"rfc6979 regression - message A").digest(), "big")
    z2 = int.from_bytes(hashlib.sha256(b"rfc6979 regression - message B").digest(), "big")

    k1_embit = embit_key.deterministic_k(TEST_SECRET_INT, z1)
    k2_embit = embit_key.deterministic_k(TEST_SECRET_INT, z2)
    k1_ref = independent_rfc6979_k(TEST_SECRET_INT, z1)
    k2_ref = independent_rfc6979_k(TEST_SECRET_INT, z2)

    assert k1_embit == k1_ref
    assert k2_embit == k2_ref
    assert k1_embit != k2_embit


def test_production_signing_path_matches_independent_rfc6979_reference():
    """Exercises ec.PrivateKey.sign() - the exact function psbt.sign_with() calls -
    on whichever secp256k1 backend actually loaded (C ctypes or pure python), and
    cross-checks its output against nonces computed with zero embit code involved."""
    prv = ec.PrivateKey(TEST_SECRET_INT.to_bytes(32, "big"))

    msg1 = hashlib.sha256(b"rfc6979 regression - message A").digest()
    msg2 = hashlib.sha256(b"rfc6979 regression - message B").digest()

    sig1a = prv.sign(msg1, grind=False)
    sig1b = prv.sign(msg1, grind=False)
    sig2 = prv.sign(msg2, grind=False)

    # same message -> byte-identical signature (deterministic, not random)
    assert sig1a.serialize() == sig1b.serialize()
    # different message -> different signature (no nonce reuse)
    assert sig1a.serialize() != sig2.serialize()

    z1 = int.from_bytes(msg1, "big")
    z2 = int.from_bytes(msg2, "big")
    r1_expected = _r_from_k(independent_rfc6979_k(TEST_SECRET_INT, z1))
    r2_expected = _r_from_k(independent_rfc6979_k(TEST_SECRET_INT, z2))

    assert _der_extract_r(sig1a.serialize()) == r1_expected
    assert _der_extract_r(sig2.serialize()) == r2_expected


def test_sign_message_call_site_is_deterministic_and_collision_free():
    """Exercises the actual seedsigner.helpers.embit_utils.sign_message() call site
    used by the message-signing feature (seed_views.py)."""
    seed_bytes = (hashlib.sha256(b"rfc6979 regression seed - not a real wallet").digest() * 2)

    sig_a1 = embit_utils.sign_message(seed_bytes, "m/44h/0h/0h/0/0", b"message one")
    sig_a2 = embit_utils.sign_message(seed_bytes, "m/44h/0h/0h/0/0", b"message one")
    sig_b = embit_utils.sign_message(seed_bytes, "m/44h/0h/0h/0/0", b"message two - different")

    assert sig_a1 == sig_a2
    assert sig_a1 != sig_b


def test_no_nonce_collisions_across_many_signatures_with_same_key():
    prv = ec.PrivateKey(TEST_SECRET_INT.to_bytes(32, "big"))

    n = 1000
    seen_r = set()
    for i in range(n):
        msg = hashlib.sha256(f"rfc6979 regression collision check {i}".encode()).digest()
        sig = prv.sign(msg, grind=False)
        r = _der_extract_r(sig.serialize())
        assert r not in seen_r
        seen_r.add(r)

    assert len(seen_r) == n
