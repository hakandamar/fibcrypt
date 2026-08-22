import hashlib
from typing import Union


def hash_to_int(data: Union[str, bytes]) -> int:
    """Hash text or bytes with SHA-256 and return the digest as an integer."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return int.from_bytes(hashlib.sha256(data).digest(), byteorder="big")
