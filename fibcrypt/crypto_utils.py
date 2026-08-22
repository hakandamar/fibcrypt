import hashlib
import hmac
import logging
import os
import threading
from enum import Enum
from typing import Dict, Optional, Tuple

from Cryptodome.Cipher import AES, ChaCha20_Poly1305
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

_CHACHA_NONCE_SIZE = 12
_CHACHA_VERSION = b"FC5"
_CHACHA_REPLAY_VERSION = b"FC6"


class CipherMode(Enum):
    AES_GCM = "aes-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


def int_to_bytes(val: int, length: int) -> bytes:
    mask = (1 << (length * 8)) - 1
    return (val & mask).to_bytes(length, byteorder="big")


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


def _encrypt_aes_gcm(
    plaintext: str,
    password: str,
    salt: str,
    pepper: str,
    iterations: int,
    prime: int,
    *,
    random_salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    version: bytes = _VERSION,
    sequence_number: Optional[int] = None,
    aad: bytes = b"",
) -> bytes:
    if random_salt is None:
        random_salt = os.urandom(_SALT_SIZE)
    key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
    if nonce is None:
        nonce = os.urandom(_GCM_NONCE_SIZE)
    if sequence_number is not None:
        header = version + sequence_number.to_bytes(_SEQUENCE_SIZE, "big")
    else:
        header = version
    header += random_salt + nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_SIZE)
    cipher.update(header + aad)
    encrypted, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return header + encrypted + tag


def _encrypt_chacha20(
    plaintext: str,
    password: str,
    salt: str,
    pepper: str,
    iterations: int,
    prime: int,
    *,
    random_salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
    version: bytes = _CHACHA_VERSION,
    sequence_number: Optional[int] = None,
    aad: bytes = b"",
) -> bytes:
    if random_salt is None:
        random_salt = os.urandom(_SALT_SIZE)
    key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
    if nonce is None:
        nonce = os.urandom(_CHACHA_NONCE_SIZE)
    if sequence_number is not None:
        header = version + sequence_number.to_bytes(_SEQUENCE_SIZE, "big")
    else:
        header = version
    header += random_salt + nonce
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(header + aad)
    encrypted, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return header + encrypted + tag


def _decrypt_aes_gcm(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    iterations: int,
    prime: int,
    *,
    aad: bytes = b"",
    replay_guard: Optional[ReplayGuard] = None,
) -> str:
    version = ciphertext[:3]
    if version == _REPLAY_VERSION:
        header_size = len(_REPLAY_VERSION) + _SEQUENCE_SIZE + _SALT_SIZE + _GCM_NONCE_SIZE
        if len(ciphertext) < header_size + _TAG_SIZE:
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
        if replay_guard is not None and not replay_guard.accept(sequence_number):
            raise ValueError("Replay detected or sequence number outside replay window")
        return plaintext.decode("utf-8")
    else:
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
        cipher.update(header + aad)
        try:
            plaintext = cipher.decrypt_and_verify(encrypted, tag)
        except ValueError as exc:
            raise ValueError("Ciphertext authentication failed") from exc
        return plaintext.decode("utf-8")


def _decrypt_chacha20(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    iterations: int,
    prime: int,
    *,
    aad: bytes = b"",
    replay_guard: Optional[ReplayGuard] = None,
) -> str:
    version = ciphertext[:3]
    if version == _CHACHA_REPLAY_VERSION:
        header_size = len(_CHACHA_REPLAY_VERSION) + _SEQUENCE_SIZE + _SALT_SIZE + _CHACHA_NONCE_SIZE
        if len(ciphertext) < header_size + _TAG_SIZE:
            raise ValueError("Unsupported or malformed replay-protected chacha ciphertext")
        sequence_end = len(_CHACHA_REPLAY_VERSION) + _SEQUENCE_SIZE
        random_salt_start = sequence_end
        random_salt_end = random_salt_start + _SALT_SIZE
        nonce_end = random_salt_end + _CHACHA_NONCE_SIZE
        version_len = len(_CHACHA_REPLAY_VERSION)
        sequence_number = int.from_bytes(
            ciphertext[version_len:sequence_end], "big"
        )
        random_salt = ciphertext[random_salt_start:random_salt_end]
        nonce = ciphertext[random_salt_end:nonce_end]
        header = ciphertext[:nonce_end]
        encrypted = ciphertext[nonce_end:-_TAG_SIZE]
        tag = ciphertext[-_TAG_SIZE:]
        key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(header + aad)
        try:
            plaintext = cipher.decrypt_and_verify(encrypted, tag)
        except ValueError as exc:
            raise ValueError("Ciphertext authentication failed") from exc
        if replay_guard is not None and not replay_guard.accept(sequence_number):
            raise ValueError("Replay detected or sequence number outside replay window")
        return plaintext.decode("utf-8")
    else:
        minimum_size = len(_CHACHA_VERSION) + _SALT_SIZE + _CHACHA_NONCE_SIZE + _TAG_SIZE
        if len(ciphertext) < minimum_size or not ciphertext.startswith(_CHACHA_VERSION):
            raise ValueError("Unsupported or malformed chacha ciphertext")
        random_salt_start = len(_CHACHA_VERSION)
        random_salt_end = random_salt_start + _SALT_SIZE
        nonce_end = random_salt_end + _CHACHA_NONCE_SIZE
        random_salt = ciphertext[random_salt_start:random_salt_end]
        nonce = ciphertext[random_salt_end:nonce_end]
        header = ciphertext[:nonce_end]
        encrypted = ciphertext[nonce_end:-_TAG_SIZE]
        tag = ciphertext[-_TAG_SIZE:]
        key = _derive_encryption_key(password, salt, pepper, random_salt, iterations, prime)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(header + aad)
        try:
            plaintext = cipher.decrypt_and_verify(encrypted, tag)
        except ValueError as exc:
            raise ValueError("Ciphertext authentication failed") from exc
        return plaintext.decode("utf-8")


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


class CryptoContext:
    """Configured encryption context with optional replay protection and key caching."""

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
        cipher_mode: CipherMode = CipherMode.AES_GCM,
    ) -> None:
        _validate_pepper(pepper)
        self.password = password
        self.salt = salt
        self.pepper = pepper
        self.iterations = iterations
        self.prime = prime
        self.replay_protection = replay_protection
        self.replay_guard = ReplayGuard(replay_window) if replay_protection else None
        self.cipher_mode = cipher_mode
        self._key_cache: "Dict[tuple, bytes]" = {}
        self._cache_lock = threading.Lock()

    def _get_cached_key(self, random_salt: bytes, domain: str = "encryption") -> bytes:
        cache_key = (
            self.password,
            self.salt,
            self.pepper,
            random_salt,
            domain,
            self.iterations,
            self.prime,
        )
        with self._cache_lock:
            if cache_key not in self._key_cache:
                derivation_salt = f"{self.salt}:{random_salt.hex()}:{domain}"
                self._key_cache[cache_key] = int_to_bytes(
                    derive_key(
                        self.password,
                        derivation_salt,
                        self.pepper,
                        self.iterations,
                        self.prime,
                    ),
                    32,
                )
            return self._key_cache[cache_key]

    def _encrypt_with_cached_key(
        self,
        plaintext: str,
        *,
        sequence_number: Optional[int] = None,
        aad: bytes = b"",
    ) -> bytes:
        random_salt = os.urandom(_SALT_SIZE)
        _ = self._get_cached_key(random_salt)
        if self.cipher_mode == CipherMode.CHACHA20_POLY1305:
            return _encrypt_chacha20(
                plaintext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                random_salt=random_salt,
                version=_CHACHA_REPLAY_VERSION if self.replay_protection else _CHACHA_VERSION,
                sequence_number=sequence_number,
                aad=aad,
            )
        else:
            return _encrypt_aes_gcm(
                plaintext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                random_salt=random_salt,
                version=_REPLAY_VERSION if self.replay_protection else _VERSION,
                sequence_number=sequence_number,
                aad=aad,
            )

    def _decrypt_with_cached_key(
        self,
        ciphertext: bytes,
        *,
        aad: bytes = b"",
    ) -> str:
        version = ciphertext[:3]
        if version in (_REPLAY_VERSION, _VERSION):
            return _decrypt_aes_gcm(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                aad=aad,
                replay_guard=self.replay_guard,
            )
        elif version in (_CHACHA_REPLAY_VERSION, _CHACHA_VERSION):
            return _decrypt_chacha20(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                aad=aad,
                replay_guard=self.replay_guard,
            )
        else:
            return _decrypt_legacy(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
            )

    def encrypt(
        self,
        plaintext: str,
        *,
        sequence_number: Optional[int] = None,
        aad: bytes = b"",
    ) -> bytes:
        if not self.replay_protection:
            return self._encrypt_with_cached_key(plaintext, aad=aad)
        return self._encrypt_with_cached_key(
            plaintext,
            sequence_number=_require_sequence_number(sequence_number),
            aad=aad,
        )

    def decrypt(self, ciphertext: bytes, *, aad: bytes = b"") -> str:
        return self._decrypt_with_cached_key(ciphertext, aad=aad)

    def clear_cache(self) -> None:
        """Clear the derived key cache."""
        with self._cache_lock:
            self._key_cache.clear()


def encrypt(
    plaintext: str,
    password: str,
    salt: str,
    pepper: str,
    iterations: int = 128,
    prime: int = DEFAULT_PRIME,
    cipher_mode: CipherMode = CipherMode.AES_GCM,
) -> bytes:
    """Encrypt plaintext with AES-GCM or ChaCha20-Poly1305 and authenticate it in one operation."""
    _validate_pepper(pepper)
    if cipher_mode == CipherMode.CHACHA20_POLY1305:
        return _encrypt_chacha20(
            plaintext, password, salt, pepper, iterations, prime
        )
    return _encrypt_aes_gcm(
        plaintext, password, salt, pepper, iterations, prime
    )


def decrypt(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    iterations: int = 128,
    prime: int = DEFAULT_PRIME,
) -> str:
    """Authenticate and decrypt an FC3/FC5 AES-GCM/ChaCha20 or legacy FC2 payload."""
    _validate_pepper(pepper)
    version = ciphertext[:3]
    if version == _LEGACY_VERSION:
        return _decrypt_legacy(ciphertext, password, salt, pepper, iterations, prime)
    elif version in (_VERSION, _REPLAY_VERSION):
        return _decrypt_aes_gcm(ciphertext, password, salt, pepper, iterations, prime)
    elif version in (_CHACHA_VERSION, _CHACHA_REPLAY_VERSION):
        return _decrypt_chacha20(ciphertext, password, salt, pepper, iterations, prime)
    else:
        raise ValueError("Unsupported or malformed ciphertext")