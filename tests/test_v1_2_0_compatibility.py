import json
from pathlib import Path
from typing import Any, Dict

import pytest

from fibcrypt.crypto_utils import CipherMode, CryptoContext, decrypt

FIXTURE = json.loads(
    (Path(__file__).with_name("v1_2_0_ciphertexts.json")).read_text(encoding="utf-8")
)
CREDENTIALS = FIXTURE["credentials"]
PASSWORD = CREDENTIALS["password"]
SALT = CREDENTIALS["salt"]
PEPPER = CREDENTIALS["pepper"]


def _vector(name: str) -> Dict[str, Any]:
    return FIXTURE["vectors"][name]


@pytest.mark.parametrize("name", ["FC3", "FC5"])
def test_v120_stateless_ciphertexts_decrypt(name: str) -> None:
    vector = _vector(name)
    ciphertext = bytes.fromhex(vector["ciphertext"])

    assert ciphertext.startswith(name.encode("ascii"))
    assert decrypt(
        ciphertext,
        PASSWORD,
        SALT,
        PEPPER,
        vector["iterations"],
        int(vector["prime"]),
    ) == vector["plaintext"]


@pytest.mark.parametrize("name", ["FC4", "FC6"])
def test_v120_replay_context_ciphertexts_decrypt(name: str) -> None:
    vector = _vector(name)
    context = CryptoContext(
        PASSWORD,
        SALT,
        PEPPER,
        replay_protection=vector["replay_protection"],
        iterations=vector["iterations"],
        prime=int(vector["prime"]),
        cipher_mode=(
            CipherMode.CHACHA20_POLY1305
            if vector["cipher"] == "chacha20-poly1305"
            else CipherMode.AES_GCM
        ),
    )

    ciphertext = bytes.fromhex(vector["ciphertext"])
    assert ciphertext.startswith(name.encode("ascii"))
    assert context.decrypt(ciphertext, aad=bytes.fromhex(vector["aad"])) == vector["plaintext"]
    with pytest.raises(ValueError, match="Replay detected"):
        context.decrypt(ciphertext, aad=bytes.fromhex(vector["aad"]))


@pytest.mark.parametrize("name", ["FC7", "FC8"])
def test_v120_session_ciphertexts_decrypt_with_context(name: str) -> None:
    vector = _vector(name)
    context = CryptoContext(
        PASSWORD,
        SALT,
        PEPPER,
        replay_protection=vector["replay_protection"],
        iterations=vector["iterations"],
        prime=int(vector["prime"]),
        cipher_mode=(
            CipherMode.CHACHA20_POLY1305
            if vector["cipher"] == "chacha20-poly1305"
            else CipherMode.AES_GCM
        ),
        high_performance=True,
        session_id=bytes.fromhex(vector["session_id"]),
        direction=vector["direction"],
    )

    ciphertext = bytes.fromhex(vector["ciphertext"])
    assert ciphertext.startswith(name.encode("ascii"))
    assert context.decrypt(ciphertext, aad=bytes.fromhex(vector["aad"])) == vector["plaintext"]
    with pytest.raises(ValueError, match="Replay detected"):
        context.decrypt(ciphertext, aad=bytes.fromhex(vector["aad"]))
