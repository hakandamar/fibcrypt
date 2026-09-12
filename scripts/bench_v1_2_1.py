#!/usr/bin/env python3
"""Measure the v1.2.1 KDF chain and FC3--FC8 operations safely.

All inputs are synthetic constants.  The report intentionally contains only
timings and environment information; it never prints credentials, plaintext,
derived keys, or ciphertexts.
"""

import argparse
import importlib.util
import itertools
import platform
import statistics
import sys
import time
from typing import Callable, Dict, List

from fibcrypt.crypto_utils import CipherMode, CryptoContext, decrypt, encrypt
from fibcrypt.kdf import DEFAULT_PRIME, derive_key

TEST_ONLY_PASSWORD = "TEST_ONLY-benchmark-password"
TEST_ONLY_SALT = "TEST_ONLY-benchmark-salt"
TEST_ONLY_PEPPER = "TEST_ONLY-benchmark-pepper-with-at-least-32-bytes"
TEST_ONLY_PLAINTEXT = "TEST_ONLY benchmark payload"
TEST_ONLY_AAD = b"TEST_ONLY/benchmark-aad"
TEST_ONLY_SESSION_ID = b"TEST_ONLY-session"[:16]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=7, help="timed samples (default: 7)")
    parser.add_argument("--warmup", type=int, default=1, help="warmup calls (default: 1)")
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")
    if args.warmup < 0:
        parser.error("--warmup must be non-negative")
    return args


def _measure(operation: Callable[[], object], samples: int, warmup: int) -> float:
    for _ in range(warmup):
        operation()
    timings: List[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        operation()
        timings.append((time.perf_counter() - started) * 1000)
    return statistics.median(timings)


def _report(results: Dict[str, float], samples: int, warmup: int) -> None:
    gmpy2_status = "available" if importlib.util.find_spec("gmpy2") else "not installed"
    print("fibcrypt v1.2.1 benchmark")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {platform.platform()}")
    print(f"gmpy2: {gmpy2_status}")
    print(f"Samples: {samples}; warmup: {warmup}; statistic: median wall-clock ms")
    print("All inputs are TEST_ONLY synthetic values; sensitive material is not printed.")
    print()
    print("Operation                                      Median ms")
    print("--------------------------------------------------------")
    for name, milliseconds in results.items():
        print(f"{name:<46} {milliseconds:>10.3f}")


def main() -> None:
    args = _parse_args()
    results: Dict[str, float] = {}

    for iterations in (128, 512, 2048):
        results[f"derive_key(iterations={iterations})"] = _measure(
            lambda iterations=iterations: derive_key(
                TEST_ONLY_PASSWORD,
                TEST_ONLY_SALT,
                TEST_ONLY_PEPPER,
                iterations=iterations,
                prime=DEFAULT_PRIME,
            ),
            args.samples,
            args.warmup,
        )

    stateless_cases = (
        ("FC3", CipherMode.AES_GCM),
        ("FC5", CipherMode.CHACHA20_POLY1305),
    )
    for marker, cipher_mode in stateless_cases:
        ciphertext = encrypt(
            TEST_ONLY_PLAINTEXT,
            TEST_ONLY_PASSWORD,
            TEST_ONLY_SALT,
            TEST_ONLY_PEPPER,
            cipher_mode=cipher_mode,
        )
        results[f"{marker} encrypt"] = _measure(
            lambda cipher_mode=cipher_mode: encrypt(
                TEST_ONLY_PLAINTEXT,
                TEST_ONLY_PASSWORD,
                TEST_ONLY_SALT,
                TEST_ONLY_PEPPER,
                cipher_mode=cipher_mode,
            ),
            args.samples,
            args.warmup,
        )
        results[f"{marker} decrypt"] = _measure(
            lambda ciphertext=ciphertext: decrypt(
                ciphertext,
                TEST_ONLY_PASSWORD,
                TEST_ONLY_SALT,
                TEST_ONLY_PEPPER,
            ),
            args.samples,
            args.warmup,
        )

    replay_cases = (
        ("FC4", CipherMode.AES_GCM),
        ("FC6", CipherMode.CHACHA20_POLY1305),
    )
    for marker, cipher_mode in replay_cases:
        sender = CryptoContext(
            TEST_ONLY_PASSWORD,
            TEST_ONLY_SALT,
            TEST_ONLY_PEPPER,
            replay_protection=True,
            cipher_mode=cipher_mode,
        )
        receiver = CryptoContext(
            TEST_ONLY_PASSWORD,
            TEST_ONLY_SALT,
            TEST_ONLY_PEPPER,
            cipher_mode=cipher_mode,
        )
        ciphertext = sender.encrypt(TEST_ONLY_PLAINTEXT, sequence_number=0, aad=TEST_ONLY_AAD)
        sequence_numbers = itertools.count(1)
        results[f"{marker} encrypt"] = _measure(
            lambda sender=sender, sequence_numbers=sequence_numbers: sender.encrypt(
                TEST_ONLY_PLAINTEXT,
                sequence_number=next(sequence_numbers),
                aad=TEST_ONLY_AAD,
            ),
            args.samples,
            args.warmup,
        )
        results[f"{marker} decrypt"] = _measure(
            lambda receiver=receiver, ciphertext=ciphertext: receiver.decrypt(
                ciphertext, aad=TEST_ONLY_AAD
            ),
            args.samples,
            args.warmup,
        )

    session_cases = (
        ("FC7", CipherMode.AES_GCM),
        ("FC8", CipherMode.CHACHA20_POLY1305),
    )
    for marker, cipher_mode in session_cases:
        def make_context() -> CryptoContext:
            return CryptoContext(
                TEST_ONLY_PASSWORD,
                TEST_ONLY_SALT,
                TEST_ONLY_PEPPER,
                cipher_mode=cipher_mode,
                high_performance=True,
                session_id=TEST_ONLY_SESSION_ID,
                direction="uplink",
            )

        results[f"{marker} session setup"] = _measure(
            make_context, args.samples, args.warmup
        )
        sender = make_context()
        receiver = make_context()
        ciphertext = sender.encrypt(TEST_ONLY_PLAINTEXT, sequence_number=0, aad=TEST_ONLY_AAD)
        sequence_numbers = itertools.count(1)
        results[f"{marker} encrypt"] = _measure(
            lambda sender=sender, sequence_numbers=sequence_numbers: sender.encrypt(
                TEST_ONLY_PLAINTEXT,
                sequence_number=next(sequence_numbers),
                aad=TEST_ONLY_AAD,
            ),
            args.samples,
            args.warmup,
        )
        results[f"{marker} decrypt"] = _measure(
            lambda receiver=receiver, ciphertext=ciphertext: receiver.decrypt(
                ciphertext, aad=TEST_ONLY_AAD
            ),
            args.samples,
            args.warmup,
        )

    _report(results, args.samples, args.warmup)


if __name__ == "__main__":
    main()
