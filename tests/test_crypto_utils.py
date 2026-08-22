import struct
from typing import Dict, Optional

import pytest
from Cryptodome.Cipher import AES

import fibcrypt.crypto_utils as crypto_utils
from fibcrypt.crypto_utils import (
    DEFAULT_PRIME,
    CipherMode,
    CryptoContext,
    decrypt,
    encrypt,
)
from fibcrypt.fib import fibonacci_mod
from fibcrypt.kdf import derive_key
from fibcrypt.utils import hash_to_int

PEPPER = "deployment-pepper-with-at-least-32-bytes"


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
