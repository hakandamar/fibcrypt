import pytest

from fibcrypt.crypto_utils import DEFAULT_PRIME, CryptoContext, decrypt, encrypt
from fibcrypt.kdf import derive_key

PEPPER = "deployment-pepper-with-at-least-32-bytes"


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


def test_replay_protection_rejects_duplicate_sequence() -> None:
    sender = CryptoContext("password", "salt", PEPPER, replay_protection=True)
    receiver = CryptoContext("password", "salt", PEPPER, replay_protection=True)
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
