import hashlib
import hmac
import logging
import struct

from fibcrypt.fib import fibonacci_mod

DEFAULT_PRIME = 2**256 - 2**32 - 977
MIN_PEPPER_BYTES = 32
logger = logging.getLogger(__name__)


def _encode_fields(*values: str) -> bytes:
    encoded = bytearray()
    for value in values:
        field = value.encode("utf-8")
        encoded.extend(struct.pack(">I", len(field)))
        encoded.extend(field)
    return bytes(encoded)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-Hash(salt, IKM)"""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: expand PRK with info to produce output keying material."""
    if length > 255 * 32:
        raise ValueError("Requested length too large for HKDF-Expand")
    output = bytearray()
    counter = 1
    prev = b""
    while len(output) < length:
        h = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256)
        prev = h.digest()
        output.extend(prev)
        counter += 1
    return bytes(output[:length])


def _derive_seed(password: str, salt: str, pepper: str) -> int:
    """
    Derive a 256-bit seed using HKDF for proper pepper mixing and domain separation.
    This replaces the simple concatenation with a standard key derivation construction.
    """
    pepper_bytes = pepper.encode("utf-8")
    if len(pepper_bytes) < MIN_PEPPER_BYTES:
        raise ValueError(f"pepper must be at least {MIN_PEPPER_BYTES} bytes")

    ikm = _encode_fields("fibcrypt-kdf-v2", password, salt)
    prk = _hkdf_extract(pepper_bytes, ikm)
    okm = _hkdf_expand(prk, b"fibcrypt-seed", 32)
    return int.from_bytes(okm, byteorder="big")


def derive_key(
    password: str,
    salt: str,
    pepper: str,
    iterations: int = 128,
    prime: int = DEFAULT_PRIME,
) -> int:
    """
    Derives a cryptographic key using a Fibonacci-based PRNG mechanism.
    Note: The default iteration count is 128 to balance security and performance.
    You may increase this value (e.g. 1000) in production for higher entropy,
    especially on faster machines.
    """
    seed = _derive_seed(password, salt, pepper)
    key = 0
    for i in range(iterations):
        key ^= fibonacci_mod(seed + i, prime)
    logger.debug("KDF completed: iterations=%d", iterations)
    return key