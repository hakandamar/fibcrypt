"""Regression tests for the v1.2.2 security-review remediations.

Covers F-1 (session-mode sender sequence monotonicity), F-2 (unguarded
FC4/FC6 decryption warning and ``strict_replay``), and F-3 (default
direction warning for high-performance contexts).
"""

import logging
import threading

import pytest

from fibcrypt.crypto_utils import (
    CipherMode,
    CryptoContext,
    decrypt,
)

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
