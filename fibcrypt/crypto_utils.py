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
from fibcrypt.kdf import (
    DEFAULT_PRIME,
    MIN_PEPPER_BYTES,
    _derive_legacy_fc3_key,
    _validate_kdf_parameters,
    derive_key,
)
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
_HIGH_PERFORMANCE_AES_VERSION = b"FC7"
_HIGH_PERFORMANCE_CHACHA_VERSION = b"FC8"
_SESSION_ID_SIZE = 16
_KEY_CACHE_SIZE = 128


class CipherMode(Enum):
    """Authenticated-encryption modes supported by the public API."""

    AES_GCM = "aes-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


def int_to_bytes(val: int, length: int) -> bytes:
    """Return ``val`` as a fixed-width big-endian byte string."""

    if val < 0 or val >= 1 << (length * 8):
        raise ValueError("integer does not fit in requested byte length")
    return val.to_bytes(length, byteorder="big")


def _derive_encryption_key(
    password: str,
    salt: str,
    pepper: str,
    random_salt: bytes,
    iterations: int,
    prime: int,
) -> bytes:
    """Derive the current per-payload encryption key for FC3/FC4 data."""

    derivation_salt = f"{salt}:{random_salt.hex()}:encryption"
    return int_to_bytes(
        derive_key(password, derivation_salt, pepper, iterations, prime), 32
    )


def _derive_legacy_fc3_encryption_key(
    password: str,
    salt: str,
    pepper: str,
    random_salt: bytes,
    iterations: int,
    prime: int,
) -> bytes:
    """Derive the pre-HKDF encryption key needed for FC3/FC4 migration."""

    derivation_salt = f"{salt}:{random_salt.hex()}:encryption"
    return int_to_bytes(
        _derive_legacy_fc3_key(password, derivation_salt, pepper, iterations, prime),
        32,
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
    """Reject deployment peppers that do not meet the minimum byte length."""

    if len(pepper.encode("utf-8")) < MIN_PEPPER_BYTES:
        raise ValueError(f"pepper must be at least {MIN_PEPPER_BYTES} bytes")


def _validate_cipher_mode(cipher_mode: CipherMode) -> None:
    """Validate that a caller selected a supported cipher enum value."""

    if not isinstance(cipher_mode, CipherMode):
        raise ValueError("cipher_mode must be a CipherMode value")


def _validate_session_id(session_id: Optional[bytes]) -> None:
    """Validate the fixed-width identifier used by FC7/FC8 sessions."""

    if session_id is not None and (
        not isinstance(session_id, bytes) or len(session_id) != _SESSION_ID_SIZE
    ):
        raise ValueError(f"session_id must be exactly {_SESSION_ID_SIZE} bytes")


def _validate_direction(direction: str) -> None:
    """Validate the direction label used for session-key domain separation."""

    if not isinstance(direction, str) or not direction:
        raise ValueError("direction must be a non-empty string")


class ReplayGuard:
    """Thread-safe sliding-window state for authenticated sequence numbers.

    The window stores the highest accepted sequence number and a bitmask of
    previously accepted values behind it. Bit zero represents the highest
    value; older values occupy progressively higher bits.
    """

    def __init__(self, window_size: int = 64) -> None:
        """Create a replay window containing at most ``window_size`` values."""

        if window_size < 1 or window_size > 64:
            raise ValueError("window_size must be between 1 and 64")
        self.window_size = window_size
        self._highest_seen: Optional[int] = None
        self._seen = 0
        self._lock = threading.Lock()

    def accept(self, sequence_number: int) -> bool:
        """Accept a new sequence number unless it is duplicate or too old."""

        if sequence_number < 0 or sequence_number >= 2**64:
            return False
        with self._lock:
            if self._highest_seen is None:
                self._highest_seen = sequence_number
                self._seen = 1
                return True
            if sequence_number > self._highest_seen:
                shift = sequence_number - self._highest_seen
                # Shift the history toward older values and mark the new high bit.
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


def _require_sequence_number(
    sequence_number: Optional[int], feature: str = "replay protection"
) -> int:
    """Validate and return an unsigned 64-bit sequence number."""

    if sequence_number is None:
        raise ValueError(f"sequence_number is required when {feature} is enabled")
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
    """Encrypt one AES-GCM payload in the FC3 or FC4 wire format."""

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
    """Encrypt one ChaCha20-Poly1305 payload in the FC5 or FC6 format."""

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


def _session_nonce(sequence_number: int) -> bytes:
    """Build a 96-bit nonce from a session-unique 64-bit sequence number.

    The sequence number must never repeat for the same session ID and
    direction. The four-byte zero prefix expands the 64-bit counter to the
    96-bit nonce size required by both supported AEAD implementations.
    """

    return b"\0" * 4 + sequence_number.to_bytes(_SEQUENCE_SIZE, "big")


def _derive_session_key(
    password: str,
    salt: str,
    pepper: str,
    session_id: bytes,
    direction: str,
    version: bytes,
    iterations: int,
    prime: int,
) -> bytes:
    """Derive the single cached key used by one FC7 or FC8 session.

    The session ID, direction, and wire-format version are part of the KDF
    domain so that keys cannot be reused across traffic directions or cipher
    formats.
    """

    direction_hex = direction.encode("utf-8").hex()
    derivation_salt = (
        f"{salt}:{session_id.hex()}:session:{direction_hex}:{version.decode('ascii')}"
    )
    return int_to_bytes(
        derive_key(password, derivation_salt, pepper, iterations, prime), 32
    )


def _encrypt_high_performance_aes(
    plaintext: str,
    key: bytes,
    session_id: bytes,
    sequence_number: int,
    aad: bytes,
) -> bytes:
    """Encrypt one FC7 AES-GCM message using a pre-derived session key."""

    header = (
        _HIGH_PERFORMANCE_AES_VERSION
        + session_id
        + sequence_number.to_bytes(_SEQUENCE_SIZE, "big")
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=_session_nonce(sequence_number), mac_len=_TAG_SIZE)
    cipher.update(header + aad)
    encrypted, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return header + encrypted + tag


def _encrypt_high_performance_chacha20(
    plaintext: str,
    key: bytes,
    session_id: bytes,
    sequence_number: int,
    aad: bytes,
) -> bytes:
    """Encrypt one FC8 ChaCha20-Poly1305 message using a session key."""

    header = (
        _HIGH_PERFORMANCE_CHACHA_VERSION
        + session_id
        + sequence_number.to_bytes(_SEQUENCE_SIZE, "big")
    )
    cipher = ChaCha20_Poly1305.new(key=key, nonce=_session_nonce(sequence_number))
    cipher.update(header + aad)
    encrypted, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return header + encrypted + tag


def _decrypt_high_performance_aes(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    direction: str,
    iterations: int,
    prime: int,
    *,
    aad: bytes = b"",
    replay_guard: Optional[ReplayGuard] = None,
    encryption_key: Optional[bytes] = None,
) -> str:
    """Authenticate and decrypt an FC7 AES-GCM session payload."""

    header_size = 3 + _SESSION_ID_SIZE + _SEQUENCE_SIZE
    if len(ciphertext) < header_size + _TAG_SIZE or not ciphertext.startswith(
        _HIGH_PERFORMANCE_AES_VERSION
    ):
        raise ValueError("Unsupported or malformed FC7 ciphertext")
    session_id_start = len(_HIGH_PERFORMANCE_AES_VERSION)
    session_id_end = session_id_start + _SESSION_ID_SIZE
    sequence_end = session_id_end + _SEQUENCE_SIZE
    session_id = ciphertext[session_id_start:session_id_end]
    sequence_number = int.from_bytes(ciphertext[session_id_end:sequence_end], "big")
    header = ciphertext[:sequence_end]
    encrypted = ciphertext[sequence_end:-_TAG_SIZE]
    tag = ciphertext[-_TAG_SIZE:]
    key = encryption_key or _derive_session_key(
        password,
        salt,
        pepper,
        session_id,
        direction,
        _HIGH_PERFORMANCE_AES_VERSION,
        iterations,
        prime,
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=_session_nonce(sequence_number), mac_len=_TAG_SIZE)
    cipher.update(header + aad)
    try:
        plaintext = cipher.decrypt_and_verify(encrypted, tag)
    except ValueError as exc:
        raise ValueError("Ciphertext authentication failed") from exc
    if replay_guard is not None and not replay_guard.accept(sequence_number):
        raise ValueError("Replay detected or sequence number outside replay window")
    return plaintext.decode("utf-8")


def _decrypt_high_performance_chacha20(
    ciphertext: bytes,
    password: str,
    salt: str,
    pepper: str,
    direction: str,
    iterations: int,
    prime: int,
    *,
    aad: bytes = b"",
    replay_guard: Optional[ReplayGuard] = None,
    encryption_key: Optional[bytes] = None,
) -> str:
    """Authenticate and decrypt an FC8 ChaCha20-Poly1305 session payload."""

    header_size = 3 + _SESSION_ID_SIZE + _SEQUENCE_SIZE
    if len(ciphertext) < header_size + _TAG_SIZE or not ciphertext.startswith(
        _HIGH_PERFORMANCE_CHACHA_VERSION
    ):
        raise ValueError("Unsupported or malformed FC8 ciphertext")
    session_id_start = len(_HIGH_PERFORMANCE_CHACHA_VERSION)
    session_id_end = session_id_start + _SESSION_ID_SIZE
    sequence_end = session_id_end + _SEQUENCE_SIZE
    session_id = ciphertext[session_id_start:session_id_end]
    sequence_number = int.from_bytes(ciphertext[session_id_end:sequence_end], "big")
    header = ciphertext[:sequence_end]
    encrypted = ciphertext[sequence_end:-_TAG_SIZE]
    tag = ciphertext[-_TAG_SIZE:]
    key = encryption_key or _derive_session_key(
        password,
        salt,
        pepper,
        session_id,
        direction,
        _HIGH_PERFORMANCE_CHACHA_VERSION,
        iterations,
        prime,
    )
    cipher = ChaCha20_Poly1305.new(key=key, nonce=_session_nonce(sequence_number))
    cipher.update(header + aad)
    try:
        plaintext = cipher.decrypt_and_verify(encrypted, tag)
    except ValueError as exc:
        raise ValueError("Ciphertext authentication failed") from exc
    if replay_guard is not None and not replay_guard.accept(sequence_number):
        raise ValueError("Replay detected or sequence number outside replay window")
    return plaintext.decode("utf-8")


def _decrypt_aes_gcm_payload(
    key: bytes,
    nonce: bytes,
    header: bytes,
    encrypted: bytes,
    tag: bytes,
    aad: bytes,
) -> bytes:
    """Authenticate and decrypt an AES-GCM payload after header parsing."""

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=_TAG_SIZE)
    cipher.update(header + aad)
    try:
        return cipher.decrypt_and_verify(encrypted, tag)
    except ValueError as exc:
        raise ValueError("Ciphertext authentication failed") from exc


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
    encryption_key: Optional[bytes] = None,
) -> str:
    """Decrypt an FC3 or FC4 AES-GCM payload and enforce replay state."""

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
        key = encryption_key or _derive_encryption_key(
            password, salt, pepper, random_salt, iterations, prime
        )
        try:
            plaintext = _decrypt_aes_gcm_payload(key, nonce, header, encrypted, tag, aad)
        except ValueError as current_exc:
            try:
                legacy_key = _derive_legacy_fc3_encryption_key(
                    password, salt, pepper, random_salt, iterations, prime
                )
                plaintext = _decrypt_aes_gcm_payload(
                    legacy_key, nonce, header, encrypted, tag, aad
                )
            except ValueError:
                raise current_exc
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
        key = encryption_key or _derive_encryption_key(
            password, salt, pepper, random_salt, iterations, prime
        )
        try:
            plaintext = _decrypt_aes_gcm_payload(key, nonce, header, encrypted, tag, aad)
        except ValueError as current_exc:
            try:
                legacy_key = _derive_legacy_fc3_encryption_key(
                    password, salt, pepper, random_salt, iterations, prime
                )
                plaintext = _decrypt_aes_gcm_payload(
                    legacy_key, nonce, header, encrypted, tag, aad
                )
            except ValueError:
                raise current_exc
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
    encryption_key: Optional[bytes] = None,
) -> str:
    """Decrypt an FC5 or FC6 ChaCha20-Poly1305 payload."""

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
        key = encryption_key or _derive_encryption_key(
            password, salt, pepper, random_salt, iterations, prime
        )
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
        key = encryption_key or _derive_encryption_key(
            password, salt, pepper, random_salt, iterations, prime
        )
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
    """Authenticate and decrypt the legacy FC2 AES-CBC/HMAC payload."""

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
    """Configured encryption context with caching and optional replay defense.

    Stateless contexts emit FC3/FC5 payloads. Enabling ``replay_protection``
    changes those formats to FC4/FC6 and requires a sequence number for every
    encrypted message. Enabling ``high_performance`` selects FC7/FC8 and
    derives one session key during initialization; it always requires a
    16-byte ``session_id`` and a sequence number for nonce construction.
    """

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
        high_performance: bool = False,
        session_id: Optional[bytes] = None,
        direction: str = "default",
    ) -> None:
        """Create a context and validate its wire-format configuration.

        Args:
            password: Password input for the Fibonacci-based KDF.
            salt: Public caller-provided context that must match at decryption.
            pepper: Secret deployment value of at least 32 UTF-8 bytes.
            replay_protection: Enable the in-process sliding replay window.
            replay_window: Number of recent sequence numbers to retain.
            iterations: Number of Fibonacci KDF rounds.
            prime: Positive modulus used by the Fibonacci arithmetic.
            cipher_mode: AES-GCM or ChaCha20-Poly1305.
            high_performance: Use the one-key-per-session FC7/FC8 formats.
            session_id: Exactly 16 bytes shared by both session endpoints.
            direction: Session traffic direction included in key separation.

        Raises:
            ValueError: If a parameter is invalid or session mode is
                configured without a session ID.
        """

        _validate_pepper(pepper)
        _validate_kdf_parameters(iterations, prime)
        _validate_cipher_mode(cipher_mode)
        _validate_session_id(session_id)
        if high_performance:
            _validate_direction(direction)
            if session_id is None:
                raise ValueError("session_id is required when high_performance=True")
        elif session_id is not None:
            raise ValueError("session_id requires high_performance=True")
        self.password = password
        self.salt = salt
        self.pepper = pepper
        self.iterations = iterations
        self.prime = prime
        self.replay_protection = replay_protection
        self.replay_guard = ReplayGuard(replay_window) if replay_protection else None
        self.cipher_mode = cipher_mode
        self.high_performance = high_performance
        self.direction = direction
        self.session_id = session_id
        self._key_cache: "Dict[tuple, bytes]" = {}
        self._cache_lock = threading.Lock()
        self._session_lock = threading.Lock()
        self._active_session_id: Optional[bytes] = None
        self._active_session_version: Optional[bytes] = None
        self._active_session_key: Optional[bytes] = None
        if high_performance:
            assert session_id is not None
            self._get_session_key(session_id, self._version_for_mode())

    def _get_cached_key(self, key_material: bytes, domain: str = "encryption") -> bytes:
        """Return a bounded LRU-style cached key for the given domain."""

        cache_key = (
            self.password,
            self.salt,
            self.pepper,
            key_material,
            domain,
            self.iterations,
            self.prime,
        )
        with self._cache_lock:
            cached_key = self._key_cache.pop(cache_key, None)
            if cached_key is not None:
                self._key_cache[cache_key] = cached_key
                return cached_key
            derivation_salt = f"{self.salt}:{key_material.hex()}:{domain}"
            cached_key = int_to_bytes(
                derive_key(
                    self.password,
                    derivation_salt,
                    self.pepper,
                    self.iterations,
                    self.prime,
                ),
                32,
            )
            self._key_cache[cache_key] = cached_key
            if len(self._key_cache) > _KEY_CACHE_SIZE:
                oldest_key = next(iter(self._key_cache))
                del self._key_cache[oldest_key]
            return cached_key

    def _cached_key_for_ciphertext(
        self, ciphertext: bytes, version: bytes
    ) -> Optional[bytes]:
        """Extract the random salt and retrieve a stateless payload key."""

        salt_start = len(version)
        if version in (_REPLAY_VERSION, _CHACHA_REPLAY_VERSION):
            salt_start += _SEQUENCE_SIZE
        salt_end = salt_start + _SALT_SIZE
        if len(ciphertext) < salt_end:
            return None
        return self._get_cached_key(ciphertext[salt_start:salt_end])

    def _version_for_mode(self) -> bytes:
        """Return the high-performance wire version for the selected cipher."""

        if self.cipher_mode == CipherMode.CHACHA20_POLY1305:
            return _HIGH_PERFORMANCE_CHACHA_VERSION
        return _HIGH_PERFORMANCE_AES_VERSION

    def _get_session_key(self, session_id: bytes, version: bytes) -> bytes:
        """Return the active session key, deriving it only when necessary."""

        active_key = self._active_session_key
        if (
            self._active_session_id == session_id
            and self._active_session_version == version
            and active_key is not None
        ):
            return active_key
        with self._session_lock:
            active_key = self._active_session_key
            if (
                self._active_session_id == session_id
                and self._active_session_version == version
                and active_key is not None
            ):
                return active_key
            direction_hex = self.direction.encode("utf-8").hex()
            domain = f"session:{direction_hex}:{version.decode('ascii')}"
            active_key = self._get_cached_key(session_id, domain=domain)
            self._active_session_id = session_id
            self._active_session_version = version
            self._active_session_key = active_key
            return active_key

    def _session_key_for_ciphertext(
        self, ciphertext: bytes, version: bytes
    ) -> Optional[bytes]:
        """Validate a payload session ID and return its cached session key."""

        session_id_start = len(version)
        session_id_end = session_id_start + _SESSION_ID_SIZE
        if len(ciphertext) < session_id_end:
            return None
        session_id = ciphertext[session_id_start:session_id_end]
        if self.session_id is None or session_id != self.session_id:
            raise ValueError("Ciphertext session_id does not match this context")
        return self._get_session_key(session_id, version)

    def _encrypt(
        self,
        plaintext: str,
        *,
        sequence_number: Optional[int] = None,
        aad: bytes = b"",
    ) -> bytes:
        """Select the configured wire format and encrypt one message."""

        if self.high_performance:
            session_id = self.session_id
            if session_id is None:
                raise RuntimeError("high-performance session is not initialized")
            sequence_number = _require_sequence_number(
                sequence_number, feature="high-performance mode"
            )
            version = self._version_for_mode()
            key = self._get_session_key(session_id, version)
            if self.cipher_mode == CipherMode.CHACHA20_POLY1305:
                return _encrypt_high_performance_chacha20(
                    plaintext, key, session_id, sequence_number, aad
                )
            return _encrypt_high_performance_aes(
                plaintext, key, session_id, sequence_number, aad
            )
        if self.cipher_mode == CipherMode.CHACHA20_POLY1305:
            return _encrypt_chacha20(
                plaintext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                version=_CHACHA_REPLAY_VERSION if self.replay_protection else _CHACHA_VERSION,
                sequence_number=sequence_number,
                aad=aad,
            )
        return _encrypt_aes_gcm(
            plaintext,
            self.password,
            self.salt,
            self.pepper,
            self.iterations,
            self.prime,
            version=_REPLAY_VERSION if self.replay_protection else _VERSION,
            sequence_number=sequence_number,
            aad=aad,
        )

    def _decrypt(
        self,
        ciphertext: bytes,
        *,
        aad: bytes = b"",
    ) -> str:
        """Dispatch payload parsing according to its authenticated version."""

        version = ciphertext[:3]
        if version == _HIGH_PERFORMANCE_AES_VERSION:
            if not self.high_performance:
                raise ValueError("FC7 ciphertext requires high_performance=True")
            return _decrypt_high_performance_aes(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.direction,
                self.iterations,
                self.prime,
                aad=aad,
                replay_guard=self.replay_guard,
                encryption_key=self._session_key_for_ciphertext(ciphertext, version),
            )
        if version == _HIGH_PERFORMANCE_CHACHA_VERSION:
            if not self.high_performance:
                raise ValueError("FC8 ciphertext requires high_performance=True")
            return _decrypt_high_performance_chacha20(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.direction,
                self.iterations,
                self.prime,
                aad=aad,
                replay_guard=self.replay_guard,
                encryption_key=self._session_key_for_ciphertext(ciphertext, version),
            )
        if self.high_performance:
            raise ValueError("High-performance context requires FC7 or FC8 ciphertext")
        if version == _LEGACY_VERSION:
            if self.replay_protection:
                raise ValueError("Replay protection requires an FC4 or FC6 ciphertext")
            return _decrypt_legacy(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
            )
        if version == _REPLAY_VERSION:
            return _decrypt_aes_gcm(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                aad=aad,
                replay_guard=self.replay_guard,
                encryption_key=self._cached_key_for_ciphertext(ciphertext, version),
            )
        if version == _VERSION:
            if self.replay_protection:
                raise ValueError("Replay protection requires an FC4 or FC6 ciphertext")
            return _decrypt_aes_gcm(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                aad=aad,
                encryption_key=self._cached_key_for_ciphertext(ciphertext, version),
            )
        if version == _CHACHA_REPLAY_VERSION:
            return _decrypt_chacha20(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                aad=aad,
                replay_guard=self.replay_guard,
                encryption_key=self._cached_key_for_ciphertext(ciphertext, version),
            )
        if version == _CHACHA_VERSION:
            if self.replay_protection:
                raise ValueError("Replay protection requires an FC4 or FC6 ciphertext")
            return _decrypt_chacha20(
                ciphertext,
                self.password,
                self.salt,
                self.pepper,
                self.iterations,
                self.prime,
                aad=aad,
                encryption_key=self._cached_key_for_ciphertext(ciphertext, version),
            )
        raise ValueError("Unsupported or malformed ciphertext")

    def encrypt(
        self,
        plaintext: str,
        *,
        sequence_number: Optional[int] = None,
        aad: bytes = b"",
    ) -> bytes:
        """Encrypt a message using this context's configured wire format.

        Args:
            plaintext: UTF-8 text to encrypt.
            sequence_number: Required for replay protection and session mode.
            aad: Additional authenticated data, not included in the plaintext.

        Returns:
            A versioned FC3-FC8 ciphertext payload.

        Raises:
            ValueError: If the sequence number is missing or invalid, or if
                the context configuration is invalid.
        """

        if self.replay_protection and not self.high_performance:
            sequence_number = _require_sequence_number(sequence_number)
        return self._encrypt(plaintext, sequence_number=sequence_number, aad=aad)

    def decrypt(self, ciphertext: bytes, *, aad: bytes = b"") -> str:
        """Authenticate and decrypt an FC2-FC8 payload for this context.

        Args:
            ciphertext: Versioned ciphertext returned by ``encrypt``.
            aad: Additional authenticated data supplied during encryption.

        Returns:
            The decrypted UTF-8 plaintext.

        Raises:
            ValueError: If the payload is malformed, unauthenticated, uses an
                incompatible format, or is a replay.
        """

        return self._decrypt(ciphertext, aad=aad)

    def clear_cache(self) -> None:
        """Clear the derived key cache."""
        with self._cache_lock:
            self._key_cache.clear()
        with self._session_lock:
            self._active_session_id = None
            self._active_session_version = None
            self._active_session_key = None


def encrypt(
    plaintext: str,
    password: str,
    salt: str,
    pepper: str,
    iterations: int = 128,
    prime: int = DEFAULT_PRIME,
    cipher_mode: CipherMode = CipherMode.AES_GCM,
) -> bytes:
    """Encrypt plaintext with a stateless authenticated payload format.

    AES-GCM produces FC3 data and ChaCha20-Poly1305 produces FC5 data. Use
    ``CryptoContext`` when replay protection or FC7/FC8 session mode is needed.

    Args:
        plaintext: UTF-8 text to encrypt.
        password: Password input for the Fibonacci-based KDF.
        salt: Public caller-provided context required during decryption.
        pepper: Secret deployment value of at least 32 UTF-8 bytes.
        iterations: Number of Fibonacci KDF rounds.
        prime: Positive modulus used by the Fibonacci arithmetic.
        cipher_mode: AES-GCM or ChaCha20-Poly1305.

    Returns:
        A versioned FC3 or FC5 ciphertext payload.

    Raises:
        ValueError: If credentials, KDF parameters, or the cipher mode are
            invalid.
    """

    _validate_pepper(pepper)
    _validate_kdf_parameters(iterations, prime)
    _validate_cipher_mode(cipher_mode)
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
    """Authenticate and decrypt a stateless FC2-FC6 payload.

    FC7/FC8 session payloads carry context-specific state and must be decrypted
    with ``CryptoContext.decrypt`` instead of this stateless function.

    Args:
        ciphertext: Versioned FC2, FC3, FC4, FC5, or FC6 payload.
        password: Password input used during encryption.
        salt: The same caller-provided context used during encryption.
        pepper: The same secret deployment value used during encryption.
        iterations: Number of Fibonacci KDF rounds used during encryption.
        prime: Positive modulus used during encryption.

    Returns:
        The authenticated UTF-8 plaintext.

    Raises:
        ValueError: If the payload is malformed or authentication fails.
    """

    _validate_pepper(pepper)
    _validate_kdf_parameters(iterations, prime)
    version = ciphertext[:3]
    if version == _LEGACY_VERSION:
        return _decrypt_legacy(ciphertext, password, salt, pepper, iterations, prime)
    elif version in (_VERSION, _REPLAY_VERSION):
        return _decrypt_aes_gcm(ciphertext, password, salt, pepper, iterations, prime)
    elif version in (_CHACHA_VERSION, _CHACHA_REPLAY_VERSION):
        return _decrypt_chacha20(ciphertext, password, salt, pepper, iterations, prime)
    else:
        raise ValueError("Unsupported or malformed ciphertext")
