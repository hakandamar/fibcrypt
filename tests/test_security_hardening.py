"""Regression tests for the security-review remediations.

Covers F-1 (session-mode sender sequence monotonicity), F-2 (unguarded
FC4/FC6 decryption warning and ``strict_replay``), F-3 (default direction
warning for high-performance contexts), F-4 (pepper commitment in key-cache
keys and cache lifetime), F-5 (bounded repeat-suppression of failed FC3/FC4
legacy KDF fallbacks), and F-6 (``RECOMMENDED_ITERATIONS`` guidance and the
one-time low-iterations warning on new-encryption entry points).
"""

import hashlib
import hmac
import logging
import os
import threading
from typing import Any, Iterator

import pytest
from Cryptodome.Cipher import AES

from fibcrypt import crypto_utils
from fibcrypt.crypto_utils import (
    CipherMode,
    CryptoContext,
    decrypt,
)
from fibcrypt.kdf import DEFAULT_PRIME, RECOMMENDED_ITERATIONS

PEPPER = "deployment-pepper-with-at-least-32-bytes"
SESSION_ID = b"\x01" * 16
LOGGER_NAME = "fibcrypt.crypto_utils"


def _session_context(**overrides: object) -> CryptoContext:
    kwargs = {
        "high_performance": True,
        "session_id": SESSION_ID,
        "direction": "uplink",
    }
    kwargs.update(overrides)
    return CryptoContext("password", "salt", PEPPER, **kwargs)


def _make_replay_payload(cipher_mode: CipherMode) -> bytes:
    sender = CryptoContext(
        "password", "salt", PEPPER, replay_protection=True, cipher_mode=cipher_mode
    )
    return sender.encrypt("replayable message", sequence_number=9)


# ---------------------------------------------------------------------------
# F-1: session-mode sender sequence monotonicity
# ---------------------------------------------------------------------------


def test_session_encrypt_rejects_non_increasing_sequence() -> None:
    context = _session_context()

    context.encrypt("first", sequence_number=5)
    with pytest.raises(ValueError, match="must be greater"):
        context.encrypt("replay", sequence_number=5)
    with pytest.raises(ValueError, match="must be greater"):
        context.encrypt("regression", sequence_number=4)
    assert context.encrypt("next", sequence_number=6).startswith(b"FC7")


def test_session_encrypt_rejects_non_increasing_sequence_for_chacha() -> None:
    context = _session_context(cipher_mode=CipherMode.CHACHA20_POLY1305)

    context.encrypt("first", sequence_number=1)
    with pytest.raises(ValueError, match="must be greater"):
        context.encrypt("replay", sequence_number=1)


def test_session_encrypt_accepts_increasing_sequence_round_trip() -> None:
    sender = _session_context()
    receiver = _session_context()

    ciphertexts = [
        sender.encrypt(f"message-{index}", sequence_number=index)
        for index in (0, 7, 4096, 2**64 - 1)
    ]
    assert [receiver.decrypt(ciphertext) for ciphertext in ciphertexts] == [
        "message-0",
        "message-7",
        "message-4096",
        "message-18446744073709551615",
    ]


def test_allow_sequence_reuse_accepts_repeated_sequence_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    context = _session_context(allow_sequence_reuse=True)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        context.encrypt("first", sequence_number=5)
        context.encrypt("second", sequence_number=5)
        context.encrypt("third", sequence_number=5)

    reuse_warnings = [
        record
        for record in caplog.records
        if "allow_sequence_reuse" in record.getMessage()
    ]
    assert len(reuse_warnings) == 1


def test_non_increasing_rejection_leaves_sender_state_unchanged() -> None:
    context = _session_context()

    context.encrypt("first", sequence_number=10)
    with pytest.raises(ValueError, match="must be greater"):
        context.encrypt("rejected", sequence_number=3)
    with pytest.raises(ValueError, match="must be greater"):
        context.encrypt("rejected", sequence_number=10)
    assert context.encrypt("accepted", sequence_number=11).startswith(b"FC7")


def test_decrypt_does_not_update_last_sent_sequence() -> None:
    peer = _session_context()
    context = _session_context()

    future = peer.encrypt("far future", sequence_number=100)
    assert context.decrypt(future) == "far future"

    # Decrypting sequence 100 must not raise this context's sender floor, so
    # continuing at sequence 1 still works.
    next_message = context.encrypt("next", sequence_number=1)
    assert peer.decrypt(next_message) == "next"


def test_concurrent_encrypt_rejects_duplicate_sequence() -> None:
    context = _session_context()
    barrier = threading.Barrier(2)
    errors = []
    errors_lock = threading.Lock()

    def send() -> None:
        barrier.wait()
        try:
            context.encrypt("race", sequence_number=5)
        except ValueError as exc:
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=send) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(errors) == 1
    assert context.encrypt("after race", sequence_number=6).startswith(b"FC7")


# ---------------------------------------------------------------------------
# F-2: unguarded FC4/FC6 decryption warning and strict_replay
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cipher_mode,version",
    [
        (CipherMode.AES_GCM, b"FC4"),
        (CipherMode.CHACHA20_POLY1305, b"FC6"),
    ],
)
def test_stateless_decrypt_of_replay_payload_warns(
    caplog: pytest.LogCaptureFixture, cipher_mode: CipherMode, version: bytes
) -> None:
    ciphertext = _make_replay_payload(cipher_mode)
    assert ciphertext.startswith(version)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        assert decrypt(ciphertext, "password", "salt", PEPPER) == "replayable message"

    assert any(
        "without a replay guard" in record.getMessage()
        and version.decode("ascii") in record.getMessage()
        for record in caplog.records
    )


def test_context_decrypt_of_replay_payload_without_guard_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ciphertext = _make_replay_payload(CipherMode.AES_GCM)
    receiver = CryptoContext("password", "salt", PEPPER)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        assert receiver.decrypt(ciphertext) == "replayable message"

    assert any(
        "without a replay guard" in record.getMessage()
        for record in caplog.records
    )


def test_guarded_replay_decrypt_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ciphertext = _make_replay_payload(CipherMode.AES_GCM)
    receiver = CryptoContext("password", "salt", PEPPER, replay_protection=True)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        assert receiver.decrypt(ciphertext) == "replayable message"

    assert not any(
        "without a replay guard" in record.getMessage()
        for record in caplog.records
    )


def test_stateless_decrypt_without_guard_does_not_warn_for_fc3(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from fibcrypt.crypto_utils import encrypt as stateless_encrypt

    ciphertext = stateless_encrypt("plain", "password", "salt", PEPPER)

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        assert decrypt(ciphertext, "password", "salt", PEPPER) == "plain"

    assert not any(
        "without a replay guard" in record.getMessage()
        for record in caplog.records
    )


@pytest.mark.parametrize(
    "cipher_mode",
    [CipherMode.AES_GCM, CipherMode.CHACHA20_POLY1305],
)
def test_strict_replay_stateless_decrypt_rejects_replay_payload(
    cipher_mode: CipherMode,
) -> None:
    ciphertext = _make_replay_payload(cipher_mode)

    with pytest.raises(ValueError, match="strict_replay"):
        decrypt(ciphertext, "password", "salt", PEPPER, strict_replay=True)


def test_strict_replay_stateless_decrypt_accepts_stateless_payload() -> None:
    from fibcrypt.crypto_utils import encrypt as stateless_encrypt

    ciphertext = stateless_encrypt("plain", "password", "salt", PEPPER)

    assert decrypt(ciphertext, "password", "salt", PEPPER, strict_replay=True) == "plain"


def test_strict_replay_context_rejects_unguarded_replay_payload() -> None:
    ciphertext = _make_replay_payload(CipherMode.AES_GCM)
    receiver = CryptoContext("password", "salt", PEPPER, strict_replay=True)

    with pytest.raises(ValueError, match="strict_replay"):
        receiver.decrypt(ciphertext)


def test_strict_replay_context_allows_guarded_replay_payload() -> None:
    ciphertext = _make_replay_payload(CipherMode.AES_GCM)
    receiver = CryptoContext(
        "password", "salt", PEPPER, replay_protection=True, strict_replay=True
    )

    assert receiver.decrypt(ciphertext) == "replayable message"
    with pytest.raises(ValueError, match="Replay detected"):
        receiver.decrypt(ciphertext)


# ---------------------------------------------------------------------------
# F-3: default direction warning for high-performance contexts
# ---------------------------------------------------------------------------


def test_default_direction_high_performance_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        CryptoContext(
            "password", "salt", PEPPER, high_performance=True, session_id=SESSION_ID
        )

    assert any(
        "default direction" in record.getMessage() for record in caplog.records
    )


def test_explicit_direction_high_performance_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        CryptoContext(
            "password",
            "salt",
            PEPPER,
            high_performance=True,
            session_id=SESSION_ID,
            direction="uplink",
        )

    assert not any(
        "default direction" in record.getMessage() for record in caplog.records
    )


def test_non_high_performance_context_does_not_warn_about_direction(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        CryptoContext("password", "salt", PEPPER)
        CryptoContext("password", "salt", PEPPER, replay_protection=True)

    assert not any(
        "default direction" in record.getMessage() for record in caplog.records
    )


# ---------------------------------------------------------------------------
# Shared fixtures and helpers for F-4/F-5/F-6
# ---------------------------------------------------------------------------


@pytest.fixture()
def reset_security_caches() -> Iterator[None]:
    """Isolate the process-wide F-5 fallback cache and F-6 warning flag."""

    crypto_utils._reset_failed_legacy_fallback_cache()
    crypto_utils._reset_low_iterations_warning()
    yield
    crypto_utils._reset_failed_legacy_fallback_cache()
    crypto_utils._reset_low_iterations_warning()


def _count_legacy_kdf_calls(monkeypatch: pytest.MonkeyPatch) -> list:
    """Wrap the legacy FC3 KDF with a call recorder for F-5 assertions."""

    calls: list = []
    original = crypto_utils._derive_legacy_fc3_encryption_key

    def counting_wrapper(*args: Any, **kwargs: Any) -> bytes:
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        crypto_utils, "_derive_legacy_fc3_encryption_key", counting_wrapper
    )
    return calls


def _corrupt_final_byte(ciphertext: bytes) -> bytes:
    """Flip one authentication-tag byte so both keys fail verification."""

    return ciphertext[:-1] + bytes([ciphertext[-1] ^ 0x01])


def _make_pre_hkdf_fc3_ciphertext(plaintext: str, pepper: str) -> bytes:
    """Build a v1.1.0-style FC3 payload that only the legacy fallback opens."""

    random_salt = os.urandom(16)
    nonce = os.urandom(12)
    key = crypto_utils._derive_legacy_fc3_encryption_key(
        "password", "salt", pepper, random_salt, 128, DEFAULT_PRIME
    )
    header = b"FC3" + random_salt + nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(header)
    encrypted, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return header + encrypted + tag


# ---------------------------------------------------------------------------
# F-4: pepper commitment in cache keys and cache lifetime
# ---------------------------------------------------------------------------


def _pepper_commitment(pepper: str) -> bytes:
    return hmac.new(
        pepper.encode("utf-8"), b"fibcrypt-cache-commitment", hashlib.sha256
    ).digest()


def test_key_cache_stores_pepper_commitment_not_raw_pepper() -> None:
    context = CryptoContext("password", "salt", PEPPER)
    ciphertext = context.encrypt("cache me")
    assert context.decrypt(ciphertext) == "cache me"

    assert context._key_cache
    for cache_key in context._key_cache:
        assert PEPPER not in cache_key
        assert PEPPER.encode("utf-8") not in cache_key
        assert _pepper_commitment(PEPPER) in cache_key


def test_cache_hit_skips_key_rederivation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = CryptoContext("password", "salt", PEPPER)
    ciphertext = context.encrypt("cache me")
    assert context.decrypt(ciphertext) == "cache me"

    derivations: list = []
    original = crypto_utils.derive_key

    def counting_derive(*args: Any, **kwargs: Any) -> int:
        derivations.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(crypto_utils, "derive_key", counting_derive)
    assert context.decrypt(ciphertext) == "cache me"
    assert derivations == []
    assert len(context._key_cache) == 1


def test_different_peppers_keep_distinct_commitments_and_keys() -> None:
    other_pepper = "second-deployment-pepper-with-32-bytes"
    assert _pepper_commitment(PEPPER) != _pepper_commitment(other_pepper)

    first = CryptoContext("password", "salt", PEPPER)
    second = CryptoContext("password", "salt", other_pepper)
    first_payload = CryptoContext("password", "salt", PEPPER).encrypt("first")
    second_payload = CryptoContext(
        "password", "salt", other_pepper
    ).encrypt("second")

    assert first.decrypt(first_payload) == "first"
    assert second.decrypt(second_payload) == "second"
    # A cache keyed by the wrong pepper commitment must not accept the other
    # pepper's payload key.
    with pytest.raises(ValueError, match="authentication failed"):
        first.decrypt(second_payload)


def test_clear_cache_rederives_and_decrypts_consistently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = CryptoContext("password", "salt", PEPPER)
    ciphertext = context.encrypt("cache me")
    assert context.decrypt(ciphertext) == "cache me"

    context.clear_cache()
    assert context._key_cache == {}

    derivations: list = []
    original = crypto_utils.derive_key

    def counting_derive(*args: Any, **kwargs: Any) -> int:
        derivations.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(crypto_utils, "derive_key", counting_derive)
    assert context.decrypt(ciphertext) == "cache me"
    assert len(derivations) == 1
    assert len(context._key_cache) == 1


# ---------------------------------------------------------------------------
# F-5: repeated failed FC3/FC4 legacy KDF fallbacks are suppressed
# ---------------------------------------------------------------------------


def test_corrupt_fc3_stateless_repeats_run_legacy_kdf_once(
    monkeypatch: pytest.MonkeyPatch, reset_security_caches: None
) -> None:
    from fibcrypt.crypto_utils import encrypt as stateless_encrypt

    calls = _count_legacy_kdf_calls(monkeypatch)
    ciphertext = _corrupt_final_byte(
        stateless_encrypt("payload", "password", "salt", PEPPER)
    )

    for _ in range(2):
        with pytest.raises(ValueError, match="Ciphertext authentication failed"):
            decrypt(ciphertext, "password", "salt", PEPPER)
    assert len(calls) == 1


def test_corrupt_fc4_context_repeats_run_legacy_kdf_once(
    monkeypatch: pytest.MonkeyPatch, reset_security_caches: None
) -> None:
    sender = CryptoContext("password", "salt", PEPPER, replay_protection=True)
    ciphertext = _corrupt_final_byte(sender.encrypt("payload", sequence_number=3))
    receiver = CryptoContext("password", "salt", PEPPER)

    calls = _count_legacy_kdf_calls(monkeypatch)
    for _ in range(3):
        with pytest.raises(ValueError, match="Ciphertext authentication failed"):
            receiver.decrypt(ciphertext)
    assert len(calls) == 1


def test_valid_pre_hkdf_fc3_payload_still_decrypts(
    reset_security_caches: None,
) -> None:
    ciphertext = _make_pre_hkdf_fc3_ciphertext("old message", PEPPER)

    assert decrypt(ciphertext, "password", "salt", PEPPER) == "old message"
    # A successful fallback must never be recorded as denied, so repeats keep
    # working (the legacy key stays derivable on demand).
    random_salt = ciphertext[3:19]
    nonce = ciphertext[19:31]
    assert not crypto_utils._legacy_fallback_denied(random_salt, nonce)
    assert decrypt(ciphertext, "password", "salt", PEPPER) == "old message"


def test_failed_legacy_fallback_cache_is_bounded_fifo(
    reset_security_caches: None,
) -> None:
    size = crypto_utils._FAILED_LEGACY_CACHE_SIZE
    oldest_salt = b"\x00" * 16
    oldest_nonce = b"\x00" * 12
    crypto_utils._remember_failed_legacy_fallback(oldest_salt, oldest_nonce)

    for index in range(1, size + 1):
        crypto_utils._remember_failed_legacy_fallback(
            index.to_bytes(16, "big"), index.to_bytes(12, "big")
        )

    assert len(crypto_utils._failed_legacy_markers) == size
    # FIFO eviction removed the oldest marker, newest ones remain denied.
    assert not crypto_utils._legacy_fallback_denied(oldest_salt, oldest_nonce)
    assert crypto_utils._legacy_fallback_denied(
        size.to_bytes(16, "big"), size.to_bytes(12, "big")
    )


# ---------------------------------------------------------------------------
# F-6: RECOMMENDED_ITERATIONS guidance warns once on new-encryption setups
# ---------------------------------------------------------------------------


def _low_iteration_warnings(caplog: pytest.LogCaptureFixture) -> list:
    return [
        record
        for record in caplog.records
        if "below the recommended" in record.getMessage()
    ]


def test_recommended_iterations_constant_is_exported() -> None:
    assert RECOMMENDED_ITERATIONS == 2048
    assert crypto_utils.RECOMMENDED_ITERATIONS == 2048
    assert "RECOMMENDED_ITERATIONS" in crypto_utils.__all__


def test_low_iterations_context_creation_warns_once(
    caplog: pytest.LogCaptureFixture, reset_security_caches: None
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        CryptoContext("password", "salt", PEPPER)
        CryptoContext("password", "salt", PEPPER, replay_protection=True)
        CryptoContext(
            "password", "salt", PEPPER, cipher_mode=CipherMode.CHACHA20_POLY1305
        )

    warnings = _low_iteration_warnings(caplog)
    assert len(warnings) == 1
    assert "iterations=128" in warnings[0].getMessage()


def test_low_iterations_stateless_encrypt_warns_once(
    caplog: pytest.LogCaptureFixture, reset_security_caches: None
) -> None:
    from fibcrypt.crypto_utils import encrypt as stateless_encrypt

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        stateless_encrypt("a", "password", "salt", PEPPER)
        stateless_encrypt(
            "b", "password", "salt", PEPPER, cipher_mode=CipherMode.CHACHA20_POLY1305
        )

    warnings = _low_iteration_warnings(caplog)
    assert len(warnings) == 1
    assert "encrypt()" in warnings[0].getMessage()


def test_recommended_iterations_setups_do_not_warn(
    caplog: pytest.LogCaptureFixture, reset_security_caches: None
) -> None:
    from fibcrypt.crypto_utils import encrypt as stateless_encrypt

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        CryptoContext("password", "salt", PEPPER, iterations=RECOMMENDED_ITERATIONS)
        stateless_encrypt(
            "a", "password", "salt", PEPPER, iterations=RECOMMENDED_ITERATIONS
        )

    assert _low_iteration_warnings(caplog) == []


def test_decrypt_paths_never_warn_about_iterations(
    caplog: pytest.LogCaptureFixture, reset_security_caches: None
) -> None:
    from fibcrypt.crypto_utils import encrypt as stateless_encrypt

    context = CryptoContext("password", "salt", PEPPER)
    context_payload = context.encrypt("payload")
    stateless_payload = stateless_encrypt("payload", "password", "salt", PEPPER)

    # Re-arm the one-time flag after setup so only decrypt calls can warn.
    crypto_utils._reset_low_iterations_warning()
    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        caplog.clear()
        assert context.decrypt(context_payload) == "payload"
        assert decrypt(stateless_payload, "password", "salt", PEPPER) == "payload"

    assert _low_iteration_warnings(caplog) == []
