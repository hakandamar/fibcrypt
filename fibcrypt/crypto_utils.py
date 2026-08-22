import hashlib
import hmac
import logging
import os
import threading
from typing import Optional, Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

from fibcrypt.fib import fibonacci_mod
from fibcrypt.kdf import DEFAULT_PRIME, MIN_PEPPER_BYTES, derive_key
from fibcrypt.utils import hash_to_int

logger = logging.getLogger(__name__)

_LEGACY_VERSION = b"FC2"
_VERSION = b"FC3"
_SALT_SIZE = 16
_GCM_NONCE_SIZE = 12
_TAG_SIZE = 16
_IV_SIZE = 16
_LEGACY_TAG_SIZE = hashlib.sha256().digest_size
_REPLAY_VERSION = b"FC4"
_SEQUENCE_SIZE = 8


def int_to_bytes(val: int, length: int) -> bytes:
    return val.to_bytes(length, byteorder="big")


def _derive_encryption_key(
    password: str,
    salt: str,
    pepper: str,
    random_salt: bytes,
    iterations: int,
    prime: int,
) -> bytes:
    derivation_salt = f"{salt}:{random_salt.hex()}:encryption"
    return int_to_bytes(
        derive_key(password, derivation_salt, pepper, iterations, prime), 32
    )


def _derive_legacy_keys(
    password: str,
    salt: str,
    pepper: str,
    random_salt: bytes,
    iterations: int,
    prime: int,
) -> Tuple[bytes, bytes]:
    """Derive FC2 keys without applying the new KDF encoding to old data."""
    derivation_salt = f"{salt}:{random_salt.hex()}"

    def legacy_key(domain: str) -> bytes:
        seed = hash_to_int(password + "\0" + derivation_salt + ":" + domain + "\0" + pepper)
        value = 0
        for index in range(iterations):
            value ^= fibonacci_mod(seed + index, prime)
        return int_to_bytes(value, 32)

    return legacy_key("encryption"), legacy_key("authentication")


def _validate_pepper(pepper: str) -> None:
    if len(pepper.encode("utf-8")) < MIN_PEPPER_BYTES:
        raise ValueError(f"pepper must be at least {MIN_PEPPER_BYTES} bytes")


class ReplayGuard:
    """Thread-safe sliding-window state for authenticated sequence numbers."""

    def __init__(self, window_size: int = 64) -> None:
        if window_size < 1 or window_size > 64:
            raise ValueError("window_size must be between 1 and 64")
        self.window_size = window_size
        self._highest_seen: Optional[int] = None
        self._seen = 0
        self._lock = threading.Lock()

    def accept(self, sequence_number: int) -> bool:
        if sequence_number < 0 or sequence_number >= 2**64:
            return False
        with self._lock:
            if self._highest_seen is None:
                self._highest_seen = sequence_number
                self._seen = 1
                return True
            if sequence_number > self._highest_seen:
                shift = sequence_number - self._highest_seen
                self._seen = 1 if shift >= self.window_size else (
                    (self._seen << shift) | 1
                ) & ((1 << self.window_size) - 1)
                self._highest_seen = sequence_number
                return True
            distance = self._highest_seen - sequence_number
            if distance >= self.window_size or self._seen & (1 << distance):
                return False
            self._seen |= 1 << distance
            return True


def _require_sequence_number(sequence_number: Optional[int]) -> int:
    if sequence_number is None:
        raise ValueError("sequence_number is required when replay protection is enabled")
    if sequence_number < 0 or sequence_number >= 2**64:
        raise ValueError("sequence_number must fit in an unsigned 64-bit integer")
    return sequence_number


def _encrypt_replay_protected(
    plaintext: str,
    password: str,
    salt: str,
    pepper: str,
    sequence_number: int,
    aad: bytes,
    iterations: int,
    prime: int,
) -> bytes:
    random_salt = os.urandom(_SALT_SIZE)
    key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
    nonce = os.urandom(_GCM_NONCE_SIZE)
    header = _REPLAY_VERSION + sequence_number.to_bytes(_SEQUENCE_SIZE, "big")
    header += random_salt + nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_SIZE)
    cipher.update(header + aad)
    encrypted, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return header + encrypted + tag


def _decrypt_replay_protected(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    aad: bytes,
    replay_guard: ReplayGuard,
    iterations: int,
    prime: int,
) -> str:
    header_size = len(_REPLAY_VERSION) + _SEQUENCE_SIZE + _SALT_SIZE + _GCM_NONCE_SIZE
    if len(ciphertext) < header_size + _TAG_SIZE or not ciphertext.startswith(_REPLAY_VERSION):
        raise ValueError("Unsupported or malformed replay-protected ciphertext")
    sequence_end = len(_REPLAY_VERSION) + _SEQUENCE_SIZE
    random_salt_start = sequence_end
    random_salt_end = random_salt_start + _SALT_SIZE
    nonce_end = random_salt_end + _GCM_NONCE_SIZE
    sequence_number = int.from_bytes(ciphertext[len(_REPLAY_VERSION):sequence_end], "big")
    random_salt = ciphertext[random_salt_start:random_salt_end]
    nonce = ciphertext[random_salt_end:nonce_end]
    header = ciphertext[:nonce_end]
    encrypted = ciphertext[nonce_end:-_TAG_SIZE]
    tag = ciphertext[-_TAG_SIZE:]
    key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_SIZE)
    cipher.update(header + aad)
    try:
        plaintext = cipher.decrypt_and_verify(encrypted, tag)
    except ValueError as exc:
        raise ValueError("Ciphertext authentication failed") from exc
    if not replay_guard.accept(sequence_number):
        raise ValueError("Replay detected or sequence number outside replay window")
    return plaintext.decode("utf-8")


class CryptoContext:
    """Configured encryption context with optional replay protection."""

    def __init__(
        self,
        password: str,
        salt: str,
        pepper: str,
        *,
        replay_protection: bool = False,
        replay_window: int = 64,
        iterations: int = 128,
        prime: int = DEFAULT_PRIME,
    ) -> None:
        _validate_pepper(pepper)
        self.password = password
        self.salt = salt
        self.pepper = pepper
        self.iterations = iterations
        self.prime = prime
        self.replay_protection = replay_protection
        self.replay_guard = ReplayGuard(replay_window) if replay_protection else None

    def encrypt(
        self,
        plaintext: str,
        *,
        sequence_number: Optional[int] = None,
        aad: bytes = b"",
    ) -> bytes:
        if not self.replay_protection:
            return encrypt(
                plaintext, self.password, self.salt, self.pepper, self.iterations, self.prime
            )
        return _encrypt_replay_protected(
            plaintext,
            self.password,
            self.salt,
            self.pepper,
            _require_sequence_number(sequence_number),
            aad,
            self.iterations,
            self.prime,
        )

    def decrypt(self, ciphertext: bytes, *, aad: bytes = b"") -> str:
        if not self.replay_protection:
            return decrypt(
                ciphertext, self.password, self.salt, self.pepper, self.iterations, self.prime
            )
        if self.replay_guard is None:
            raise RuntimeError("replay guard is not initialized")
        return _decrypt_replay_protected(
            ciphertext,
            self.password,
            self.salt,
            self.pepper,
            aad,
            self.replay_guard,
            self.iterations,
            self.prime,
        )


def encrypt(
    plaintext: str,
    password: str,
    salt: str,
    pepper: str,
    iterations: int = 128,
    prime: int = DEFAULT_PRIME,
) -> bytes:
    """Encrypt plaintext with AES-GCM and authenticate it in one operation."""
    _validate_pepper(pepper)
    random_salt = os.urandom(_SALT_SIZE)
    key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
    nonce = os.urandom(_GCM_NONCE_SIZE)
    header = _VERSION + random_salt + nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_SIZE)
    cipher.update(header)
    encrypted, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    logger.debug(
        "Encryption completed: iterations=%d, plaintext_bytes=%d",
        iterations,
        len(plaintext.encode("utf-8")),
    )
    return header + encrypted + tag


def _decrypt_legacy(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    iterations: int,
    prime: int,
) -> str:
    minimum_size = len(_LEGACY_VERSION) + _SALT_SIZE + _IV_SIZE + AES.block_size + _LEGACY_TAG_SIZE
    if len(ciphertext) < minimum_size:
        raise ValueError("Unsupported or malformed ciphertext")
    random_salt_start = len(_LEGACY_VERSION)
    random_salt_end = random_salt_start + _SALT_SIZE
    iv_end = random_salt_end + _IV_SIZE
    random_salt = ciphertext[random_salt_start:random_salt_end]
    iv = ciphertext[random_salt_end:iv_end]
    payload = ciphertext[:-_LEGACY_TAG_SIZE]
    tag = ciphertext[-_LEGACY_TAG_SIZE:]
    _, mac_key = _derive_legacy_keys(password, salt, pepper, random_salt, iterations, prime)
    expected_tag = hmac.new(mac_key, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Ciphertext authentication failed")
    key, _ = _derive_legacy_keys(password, salt, pepper, random_salt, iterations, prime)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(
        cipher.decrypt(ciphertext[iv_end:-_LEGACY_TAG_SIZE]), AES.block_size
    ).decode("utf-8")


def decrypt(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    iterations: int = 128,
    prime: int = DEFAULT_PRIME,
) -> str:
    """Authenticate and decrypt an FC3 AES-GCM or legacy FC2 payload."""
    _validate_pepper(pepper)
    if ciphertext.startswith(_LEGACY_VERSION):
        return _decrypt_legacy(ciphertext, password, salt, pepper, iterations, prime)
    minimum_size = len(_VERSION) + _SALT_SIZE + _GCM_NONCE_SIZE + _TAG_SIZE
    if len(ciphertext) < minimum_size or not ciphertext.startswith(_VERSION):
        raise ValueError("Unsupported or malformed ciphertext")
    random_salt_start = len(_VERSION)
    random_salt_end = random_salt_start + _SALT_SIZE
    nonce_end = random_salt_end + _GCM_NONCE_SIZE
    random_salt = ciphertext[random_salt_start:random_salt_end]
    nonce = ciphertext[random_salt_end:nonce_end]
    header = ciphertext[:nonce_end]
    encrypted = ciphertext[nonce_end:-_TAG_SIZE]
    tag = ciphertext[-_TAG_SIZE:]
    key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_SIZE)
    cipher.update(header)
    try:
        plaintext = cipher.decrypt_and_verify(encrypted, tag)
    except ValueError as exc:
        raise ValueError("Ciphertext authentication failed") from exc
    logger.debug(
        "Decryption completed: iterations=%d, plaintext_bytes=%d",
        iterations,
        len(plaintext),
    )
    return plaintext.decode("utf-8")
