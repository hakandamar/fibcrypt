import hashlib
import hmac
import struct
from typing import Dict, Optional

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

import fibcrypt.crypto_utils as crypto_utils
from fibcrypt.crypto_utils import (
    DEFAULT_PRIME,
    CipherMode,
    CryptoContext,
    ReplayGuard,
    decrypt,
    encrypt,
    int_to_bytes,
)
from fibcrypt.fib import fibonacci_mod
from fibcrypt.kdf import _derive_seed, _hkdf_expand, derive_key
from fibcrypt.utils import hash_to_int

PEPPER = "deployment-pepper-with-at-least-32-bytes"
SESSION_ID = b"\x01" * 16


def _encode_legacy_fields(*values: str) -> bytes:
    encoded = bytearray()
    for value in values:
        field = value.encode("utf-8")
        encoded.extend(struct.pack(">I", len(field)))
        encoded.extend(field)
    return bytes(encoded)


def _make_v11_fc3_payload(sequence_number: Optional[int] = None) -> bytes:
    random_salt = bytes(range(16))
    nonce = bytes(range(16, 28))
    password = "password"
    salt = "salt"
    plaintext = b"v1.1.0 payload"
    derivation_salt = f"{salt}:{random_salt.hex()}:encryption"
    seed = hash_to_int(
        _encode_legacy_fields("fibcrypt-kdf-v2", password, derivation_salt, PEPPER)
    )
    key_value = 0
    for index in range(128):
        key_value ^= fibonacci_mod(seed + index, DEFAULT_PRIME)
    key = key_value.to_bytes(32, "big")
    version = b"FC4" if sequence_number is not None else b"FC3"
    header = version
    if sequence_number is not None:
        header += sequence_number.to_bytes(8, "big")
    header += random_salt + nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(header)
    encrypted, tag = cipher.encrypt_and_digest(plaintext)
    return header + encrypted + tag


def _make_fc2_payload() -> bytes:
    random_salt = bytes(range(16))
    iv = bytes(range(16, 32))
    plaintext = b"legacy payload"
    encryption_key, mac_key = crypto_utils._derive_legacy_keys(
        "password", "salt", PEPPER, random_salt, 1, DEFAULT_PRIME
    )
    header = b"FC2" + random_salt + iv
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    payload = header + cipher.encrypt(pad(plaintext, AES.block_size))
    tag = hmac.new(mac_key, payload, hashlib.sha256).digest()
    return payload + tag


def test_encrypt_decrypt_round_trip() -> None:
    plaintext = "Test message"

    ciphertext = encrypt(plaintext, "password", "salt", PEPPER)

    assert len(ciphertext) > 16
    assert ciphertext.startswith(b"FC3")
    assert decrypt(ciphertext, "password", "salt", PEPPER) == plaintext


def test_encrypt_uses_a_random_iv() -> None:
    first = encrypt("same message", "password", "salt", PEPPER)
    second = encrypt("same message", "password", "salt", PEPPER)

    assert first[:16] != second[:16]
    assert first != second


def test_decrypt_rejects_tampered_ciphertext() -> None:
    ciphertext = bytearray(
        encrypt("protected", "password", "salt", PEPPER)
    )
    ciphertext[-1] ^= 1

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt(bytes(ciphertext), "password", "salt", PEPPER)


def test_decrypt_rejects_wrong_pepper() -> None:
    ciphertext = encrypt("protected", "password", "salt", PEPPER)

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt(ciphertext, "password", "salt", "wrong-pepper-that-is-long-enough")


def test_default_key_fits_a_256_bit_aes_key() -> None:
    key = derive_key("password", "salt", PEPPER)

    assert 0 <= key < 2**256
    assert DEFAULT_PRIME.bit_length() == 256


def test_kdf_length_prefixes_fields() -> None:
    first = derive_key("ab\0cd", "ef", PEPPER)
    second = derive_key("ab", "cd\0ef", PEPPER)

    assert first != second


def test_short_pepper_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        encrypt("protected", "password", "salt", "too-short")


def test_v11_fc3_payload_remains_decryptable() -> None:
    ciphertext = _make_v11_fc3_payload()

    assert decrypt(ciphertext, "password", "salt", PEPPER) == "v1.1.0 payload"


def test_v11_fc4_payload_remains_replay_protected() -> None:
    sender = CryptoContext("password", "salt", PEPPER, replay_protection=True)
    ciphertext = _make_v11_fc3_payload(sequence_number=7)

    assert sender.decrypt(ciphertext) == "v1.1.0 payload"
    with pytest.raises(ValueError, match="Replay detected"):
        sender.decrypt(ciphertext)


@pytest.mark.parametrize("cipher_mode", [CipherMode.AES_GCM, CipherMode.CHACHA20_POLY1305])
def test_replay_protection_rejects_duplicate_sequence(cipher_mode: CipherMode) -> None:
    sender = CryptoContext(
        "password", "salt", PEPPER, replay_protection=True, cipher_mode=cipher_mode
    )
    receiver = CryptoContext(
        "password", "salt", PEPPER, replay_protection=True, cipher_mode=cipher_mode
    )
    ciphertext = sender.encrypt("protected", sequence_number=7)

    assert receiver.decrypt(ciphertext) == "protected"
    with pytest.raises(ValueError, match="Replay detected"):
        receiver.decrypt(ciphertext)


def test_replay_protection_requires_sequence_number() -> None:
    context = CryptoContext("password", "salt", PEPPER, replay_protection=True)

    with pytest.raises(ValueError, match="sequence_number is required"):
        context.encrypt("protected")


def test_replay_protection_authenticates_aad() -> None:
    sender = CryptoContext("password", "salt", PEPPER, replay_protection=True)
    receiver = CryptoContext("password", "salt", PEPPER, replay_protection=True)
    ciphertext = sender.encrypt("protected", sequence_number=1, aad=b"telemetry")

    with pytest.raises(ValueError, match="authentication failed"):
        receiver.decrypt(ciphertext, aad=b"control")
    assert receiver.decrypt(ciphertext, aad=b"telemetry") == "protected"


@pytest.mark.parametrize(
    "cipher_mode, version",
    [(CipherMode.AES_GCM, b"FC3"), (CipherMode.CHACHA20_POLY1305, b"FC5")],
)
def test_cipher_modes_round_trip(cipher_mode: CipherMode, version: bytes) -> None:
    ciphertext = encrypt(
        "mode message", "password", "salt", PEPPER, cipher_mode=cipher_mode
    )

    assert ciphertext.startswith(version)
    assert decrypt(ciphertext, "password", "salt", PEPPER) == "mode message"


@pytest.mark.parametrize(
    "cipher_mode", [CipherMode.AES_GCM, CipherMode.CHACHA20_POLY1305]
)
def test_replay_context_rejects_stateless_payload(cipher_mode: CipherMode) -> None:
    ciphertext = encrypt(
        "unprotected", "password", "salt", PEPPER, cipher_mode=cipher_mode
    )
    receiver = CryptoContext("password", "salt", PEPPER, replay_protection=True)

    with pytest.raises(ValueError, match="requires an FC4 or FC6"):
        receiver.decrypt(ciphertext)


@pytest.mark.parametrize(
    "cipher_mode, version",
    [
        (CipherMode.AES_GCM, b"FC7"),
        (CipherMode.CHACHA20_POLY1305, b"FC8"),
    ],
)
def test_high_performance_session_round_trip(
    cipher_mode: CipherMode, version: bytes
) -> None:
    sender = CryptoContext(
        "password",
        "salt",
        PEPPER,
        replay_protection=True,
        cipher_mode=cipher_mode,
        high_performance=True,
        session_id=SESSION_ID,
        direction="uplink",
    )
    receiver = CryptoContext(
        "password",
        "salt",
        PEPPER,
        replay_protection=True,
        cipher_mode=cipher_mode,
        high_performance=True,
        session_id=SESSION_ID,
        direction="uplink",
    )
    ciphertext = sender.encrypt("session message", sequence_number=1, aad=b"base-station")

    assert ciphertext.startswith(version)
    assert receiver.decrypt(ciphertext, aad=b"base-station") == "session message"
    with pytest.raises(ValueError, match="Replay detected"):
        receiver.decrypt(ciphertext, aad=b"base-station")


def test_high_performance_requires_sequence_number() -> None:
    context = CryptoContext(
        "password",
        "salt",
        PEPPER,
        high_performance=True,
        session_id=SESSION_ID,
    )

    with pytest.raises(ValueError, match="high-performance mode"):
        context.encrypt("session message")


def test_high_performance_requires_session_id() -> None:
    with pytest.raises(ValueError, match="session_id is required"):
        CryptoContext("password", "salt", PEPPER, high_performance=True)


def test_high_performance_derives_session_key_once(monkeypatch: pytest.MonkeyPatch) -> None:
    derive_calls = 0
    original_derive_key = crypto_utils.derive_key

    def counted_derive_key(*args: object, **kwargs: object) -> int:
        nonlocal derive_calls
        derive_calls += 1
        return original_derive_key(*args, **kwargs)

    monkeypatch.setattr(crypto_utils, "derive_key", counted_derive_key)
    sender = CryptoContext(
        "password",
        "salt",
        PEPPER,
        iterations=1,
        high_performance=True,
        session_id=SESSION_ID,
    )
    receiver = CryptoContext(
        "password",
        "salt",
        PEPPER,
        iterations=1,
        high_performance=True,
        session_id=SESSION_ID,
    )
    ciphertexts = [
        sender.encrypt(f"message-{index}", sequence_number=index)
        for index in range(3)
    ]

    assert derive_calls == 2
    assert [receiver.decrypt(ciphertext) for ciphertext in ciphertexts] == [
        "message-0",
        "message-1",
        "message-2",
    ]
    assert derive_calls == 2


def test_high_performance_context_rejects_non_session_payload() -> None:
    context = CryptoContext(
        "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
    )
    ciphertext = encrypt("normal message", "password", "salt", PEPPER)

    with pytest.raises(ValueError, match="requires FC7 or FC8"):
        context.decrypt(ciphertext)


def test_high_performance_session_binds_direction_and_aad() -> None:
    sender = CryptoContext(
        "password",
        "salt",
        PEPPER,
        high_performance=True,
        session_id=SESSION_ID,
        direction="uplink",
    )
    receiver = CryptoContext(
        "password",
        "salt",
        PEPPER,
        high_performance=True,
        session_id=SESSION_ID,
        direction="downlink",
    )
    ciphertext = sender.encrypt("session message", sequence_number=1, aad=b"telemetry")

    with pytest.raises(ValueError, match="authentication failed"):
        receiver.decrypt(ciphertext, aad=b"telemetry")

    with pytest.raises(ValueError, match="authentication failed"):
        receiver.decrypt(ciphertext, aad=b"control")


def test_high_performance_sequence_number_is_authenticated() -> None:
    sender = CryptoContext(
        "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
    )
    receiver = CryptoContext(
        "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
    )
    ciphertext = bytearray(sender.encrypt("session message", sequence_number=1))
    sequence_offset = len(b"FC7") + len(SESSION_ID)
    ciphertext[sequence_offset + 7] ^= 1

    with pytest.raises(ValueError, match="authentication failed"):
        receiver.decrypt(bytes(ciphertext))


def test_high_performance_rejects_wrong_session_id() -> None:
    sender = CryptoContext(
        "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
    )
    receiver = CryptoContext(
        "password",
        "salt",
        PEPPER,
        high_performance=True,
        session_id=b"\x02" * 16,
    )
    ciphertext = sender.encrypt("session message", sequence_number=1)

    with pytest.raises(ValueError, match="session_id"):
        receiver.decrypt(ciphertext)


def test_context_cache_is_bounded_and_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    context = CryptoContext("password", "salt", PEPPER, iterations=1)
    ciphertexts = [
        encrypt("cached", "password", "salt", PEPPER, iterations=1)
        for _ in range(crypto_utils._KEY_CACHE_SIZE + 1)
    ]
    original_derive_key = crypto_utils.derive_key
    derive_calls = 0

    def counted_derive_key(*args: object, **kwargs: object) -> int:
        nonlocal derive_calls
        derive_calls += 1
        return original_derive_key(*args, **kwargs)

    monkeypatch.setattr(crypto_utils, "derive_key", counted_derive_key)
    assert context.decrypt(ciphertexts[0]) == "cached"
    assert context.decrypt(ciphertexts[0]) == "cached"
    assert derive_calls == 1
    for ciphertext in ciphertexts[1:]:
        assert context.decrypt(ciphertext) == "cached"
    assert len(context._key_cache) == crypto_utils._KEY_CACHE_SIZE


@pytest.mark.parametrize(
    "kwargs", [{"iterations": 0}, {"iterations": -1}, {"prime": 1}]
)
def test_invalid_kdf_parameters_are_rejected(kwargs: Dict[str, int]) -> None:
    with pytest.raises(ValueError):
        encrypt("protected", "password", "salt", PEPPER, **kwargs)


def test_invalid_cipher_mode_is_rejected() -> None:
    with pytest.raises(ValueError, match="cipher_mode"):
        encrypt("protected", "password", "salt", PEPPER, cipher_mode="aes-gcm")  # type: ignore[arg-type]


@pytest.mark.parametrize("n, mod", [(-1, 65537), (1, 0)])
def test_invalid_fibonacci_arguments_are_rejected(n: int, mod: int) -> None:
    with pytest.raises(ValueError):
        fibonacci_mod(n, mod)


def test_integer_and_hash_helpers_accept_expected_inputs() -> None:
    assert int_to_bytes(255, 1) == b"\xff"
    assert hash_to_int("payload") == hash_to_int(b"payload")

    with pytest.raises(ValueError):
        int_to_bytes(-1, 1)
    with pytest.raises(ValueError):
        int_to_bytes(256, 1)


def test_kdf_edge_conditions_are_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        _derive_seed("password", "salt", "too-short")
    with pytest.raises(ValueError, match="too large"):
        _hkdf_expand(b"prk", b"info", 255 * 32 + 1)


def test_replay_guard_handles_window_boundaries() -> None:
    with pytest.raises(ValueError):
        ReplayGuard(0)
    with pytest.raises(ValueError):
        ReplayGuard(65)

    guard = ReplayGuard(window_size=4)
    assert not guard.accept(-1)
    assert not guard.accept(2**64)
    assert guard.accept(10)
    assert guard.accept(12)
    assert guard.accept(11)
    assert not guard.accept(11)
    assert not guard.accept(8)
    assert guard.accept(20)


def test_context_rejects_invalid_session_configuration() -> None:
    with pytest.raises(ValueError, match="exactly 16 bytes"):
        CryptoContext("password", "salt", PEPPER, high_performance=True, session_id=b"short")
    with pytest.raises(ValueError, match="non-empty"):
        CryptoContext(
            "password",
            "salt",
            PEPPER,
            high_performance=True,
            session_id=SESSION_ID,
            direction="",
        )
    with pytest.raises(ValueError, match="requires high_performance"):
        CryptoContext("password", "salt", PEPPER, session_id=SESSION_ID)


@pytest.mark.parametrize("sequence_number", [-1, 2**64])
def test_sequence_number_bounds_are_enforced(sequence_number: int) -> None:
    context = CryptoContext("password", "salt", PEPPER, replay_protection=True)

    with pytest.raises(ValueError, match="unsigned 64-bit"):
        context.encrypt("protected", sequence_number=sequence_number)


@pytest.mark.parametrize("payload", [b"FC2", b"FC3", b"FC4", b"FC5", b"FC6"])
def test_decrypt_rejects_truncated_payloads(payload: bytes) -> None:
    with pytest.raises(ValueError, match="Unsupported or malformed"):
        decrypt(payload, "password", "salt", PEPPER)


def test_decrypt_rejects_unknown_payload_version() -> None:
    with pytest.raises(ValueError, match="Unsupported or malformed"):
        decrypt(b"BAD", "password", "salt", PEPPER)


@pytest.mark.parametrize("payload", [b"FC7", b"FC8"])
def test_high_performance_context_rejects_truncated_payloads(payload: bytes) -> None:
    context = CryptoContext(
        "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
    )

    with pytest.raises(ValueError, match="Unsupported or malformed"):
        context.decrypt(payload)


@pytest.mark.parametrize(
    "cipher_mode, version",
    [(CipherMode.AES_GCM, b"FC7"), (CipherMode.CHACHA20_POLY1305, b"FC8")],
)
def test_standard_context_rejects_high_performance_payloads(
    cipher_mode: CipherMode, version: bytes
) -> None:
    session = CryptoContext(
        "password",
        "salt",
        PEPPER,
        cipher_mode=cipher_mode,
        high_performance=True,
        session_id=SESSION_ID,
    )
    ciphertext = session.encrypt("session message", sequence_number=1)
    context = CryptoContext("password", "salt", PEPPER, cipher_mode=cipher_mode)

    assert ciphertext.startswith(version)
    with pytest.raises(ValueError, match="high_performance=True"):
        context.decrypt(ciphertext)


@pytest.mark.parametrize("cipher_mode", [CipherMode.AES_GCM, CipherMode.CHACHA20_POLY1305])
def test_replay_payload_authentication_rejects_tampering(cipher_mode: CipherMode) -> None:
    sender = CryptoContext(
        "password", "salt", PEPPER, replay_protection=True, cipher_mode=cipher_mode
    )
    receiver = CryptoContext(
        "password", "salt", PEPPER, replay_protection=True, cipher_mode=cipher_mode
    )
    ciphertext = bytearray(sender.encrypt("protected", sequence_number=1))
    ciphertext[-1] ^= 1

    with pytest.raises(ValueError, match="authentication failed"):
        receiver.decrypt(bytes(ciphertext))


def test_stateless_chacha_authentication_rejects_tampering() -> None:
    ciphertext = bytearray(
        encrypt(
            "protected",
            "password",
            "salt",
            PEPPER,
            cipher_mode=CipherMode.CHACHA20_POLY1305,
        )
    )
    ciphertext[-1] ^= 1

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt(bytes(ciphertext), "password", "salt", PEPPER)


def test_high_performance_chacha_authentication_rejects_tampering() -> None:
    sender = CryptoContext(
        "password",
        "salt",
        PEPPER,
        cipher_mode=CipherMode.CHACHA20_POLY1305,
        high_performance=True,
        session_id=SESSION_ID,
    )
    receiver = CryptoContext(
        "password",
        "salt",
        PEPPER,
        cipher_mode=CipherMode.CHACHA20_POLY1305,
        high_performance=True,
        session_id=SESSION_ID,
    )
    ciphertext = bytearray(sender.encrypt("protected", sequence_number=1))
    ciphertext[-1] ^= 1

    with pytest.raises(ValueError, match="authentication failed"):
        receiver.decrypt(bytes(ciphertext))


def test_legacy_fc2_payload_is_decrypted_and_rejected_by_replay_context() -> None:
    ciphertext = _make_fc2_payload()

    assert decrypt(ciphertext, "password", "salt", PEPPER, iterations=1) == "legacy payload"
    context = CryptoContext("password", "salt", PEPPER, iterations=1)
    assert context.decrypt(ciphertext) == "legacy payload"

    invalid_tag = bytearray(ciphertext)
    invalid_tag[-1] ^= 1
    with pytest.raises(ValueError, match="authentication failed"):
        decrypt(bytes(invalid_tag), "password", "salt", PEPPER, iterations=1)

    replay_context = CryptoContext(
        "password", "salt", PEPPER, replay_protection=True, iterations=1
    )
    with pytest.raises(ValueError, match="requires an FC4 or FC6"):
        replay_context.decrypt(ciphertext)


def test_session_key_derivation_uses_session_domain() -> None:
    key = crypto_utils._derive_session_key(
        "password", "salt", PEPPER, SESSION_ID, "uplink", b"FC7", 1, DEFAULT_PRIME
    )

    assert len(key) == 32


def test_clear_cache_clears_stateless_and_session_keys() -> None:
    context = CryptoContext("password", "salt", PEPPER, iterations=1)
    context.decrypt(encrypt("cached", "password", "salt", PEPPER, iterations=1))
    assert context._key_cache
    context.clear_cache()
    assert not context._key_cache

    session_context = CryptoContext(
        "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
    )
    assert session_context._active_session_key is not None
    session_context.clear_cache()
    assert session_context._active_session_key is None


def test_high_performance_encrypt_requires_initialized_session() -> None:
    context = CryptoContext(
        "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
    )
    context.session_id = None

    with pytest.raises(RuntimeError, match="not initialized"):
        context.encrypt("session message", sequence_number=1)


def test_context_dispatches_stateless_chacha_payload() -> None:
    ciphertext = encrypt(
        "chacha message",
        "password",
        "salt",
        PEPPER,
        cipher_mode=CipherMode.CHACHA20_POLY1305,
    )
    context = CryptoContext("password", "salt", PEPPER)

    assert context.decrypt(ciphertext) == "chacha message"


def test_context_rejects_truncated_stateless_payload_and_unknown_version() -> None:
    context = CryptoContext("password", "salt", PEPPER)

    with pytest.raises(ValueError, match="Unsupported or malformed"):
        context.decrypt(b"FC3")
    with pytest.raises(ValueError, match="Unsupported or malformed"):
        context.decrypt(b"BAD")
