import logging
import struct

from fibcrypt.fib import fibonacci_mod
from fibcrypt.utils import hash_to_int

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


def derive_key(
    password: str,
    salt: str,
    pepper: str,
    iterations: int = 128,
    prime: int = DEFAULT_PRIME,
) -> int:
    """
    Derives a cryptographic key using a Fibonacci-based PRNG mechanism
    Note: The default iteration count is 128 to balance security and performance.
    You may increase this value (e.g. 1000) in production for higher entropy,
    especially on faster machines.
    """
    pepper_bytes = pepper.encode("utf-8")
    if len(pepper_bytes) < MIN_PEPPER_BYTES:
        raise ValueError(f"pepper must be at least {MIN_PEPPER_BYTES} bytes")

    seed = hash_to_int(_encode_fields("fibcrypt-kdf-v2", password, salt, pepper))
    key = 0
    for i in range(iterations):
        key ^= fibonacci_mod(seed + i, prime)  # XOR folding of PRNG outputs
    logger.debug("KDF completed: iterations=%d", iterations)
    return key
