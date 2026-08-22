"""Run reproducible exploratory analysis of the fibcrypt KDF.

This script is an analysis aid, not a proof of security or a replacement for
an independent cryptographic audit. It keeps the exact implementation under
test visible and separates small-modulus experiments from measurements using
the package's default 256-bit modulus.
"""

import argparse
import json
import math
import random
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, cast

from fibcrypt.crypto_utils import CipherMode, CryptoContext, decrypt, encrypt
from fibcrypt.fib import _HAS_GMPY2, fibonacci_mod
from fibcrypt.kdf import DEFAULT_PRIME, _derive_seed, derive_key

_ANALYSIS_SEED = 0xF1BC0DE
_PEPPER = "analysis-pepper-with-at-least-32-bytes"
_PASSWORD = "analysis-password"
_SALT_PREFIX = "analysis-salt-"
_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 31, 101, 257, 1009)
_SESSION_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
_FORMAT_AAD = b""


def _g(seed: int, prime: int, iterations: int = 128) -> int:
    """Match derive_key's XOR aggregation without HKDF seed derivation."""

    key = 0
    for offset in range(iterations):
        # The implementation XORs already-reduced Fibonacci values. There is
        # no final modulo operation after the XOR aggregation.
        key ^= fibonacci_mod(seed + offset, prime)
    return key


def _fibonacci_period(prime: int) -> int:
    """Return the period of (F(n), F(n+1)) modulo a small prime."""

    previous, current = 0, 1
    for period in range(1, 10_000_000):
        previous, current = current, (previous + current) % prime
        if previous == 0 and current == 1:
            return period
    raise RuntimeError(f"period search limit exceeded for prime={prime}")


def _small_prime_results() -> List[Dict[str, int]]:
    results: List[Dict[str, int]] = []
    for prime in _SMALL_PRIMES:
        period = _fibonacci_period(prime)
        outputs = [_g(seed, prime) for seed in range(period)]
        multiplicities = Counter(outputs)
        target = outputs[0]
        results.append(
            {
                "prime": prime,
                "fibonacci_period": period,
                "domain_size": period,
                "unique_outputs": len(multiplicities),
                "collision_count": period - len(multiplicities),
                "max_preimages_in_one_period": max(multiplicities.values()),
                "preimages_of_G_0": multiplicities[target],
            }
        )
    return results


def _related_output_identity(seed: int, prime: int, offset: int) -> bool:
    left = _g(seed, prime) ^ _g(seed + offset, prime)
    edge_terms: Iterable[int] = (
        fibonacci_mod(seed + index, prime) for index in range(offset)
    )
    trailing_terms: Iterable[int] = (
        fibonacci_mod(seed + 128 + index, prime) for index in range(offset)
    )
    right = 0
    for value in list(edge_terms) + list(trailing_terms):
        right ^= value
    return left == right


def _bit_statistics(values: Sequence[int]) -> Dict[str, object]:
    sample_count = len(values)
    ones = [sum((value >> bit) & 1 for value in values) for bit in range(256)]
    biases = [abs(count / sample_count - 0.5) for count in ones]
    p_values = [
        math.erfc(abs(2.0 * count - sample_count) / math.sqrt(2.0 * sample_count))
        for count in ones
    ]
    most_biased_bit = max(range(256), key=lambda bit: biases[bit])
    return {
        "samples": sample_count,
        "unique_outputs": len(set(values)),
        "min_bit_ones": min(ones),
        "max_bit_ones": max(ones),
        "mean_bit_ones": statistics.mean(ones),
        "most_biased_bit": most_biased_bit,
        "max_absolute_bit_bias": biases[most_biased_bit],
        "minimum_bit_balance_p_value": min(p_values),
        "min_output_bit_length": min(value.bit_length() for value in values),
        "max_output_bit_length": max(value.bit_length() for value in values),
    }


def _popcount(value: int) -> int:
    """Count set bits using a Python 3.8-compatible implementation."""

    return bin(value).count("1")


def _differential_statistics(
    seeds: Sequence[int], prime: int, offset: int
) -> Dict[str, float]:
    weights = [_popcount(_g(seed, prime) ^ _g(seed + offset, prime)) for seed in seeds]
    return {
        "offset": offset,
        "samples": len(weights),
        "mean_hamming_weight": statistics.mean(weights),
        "minimum_hamming_weight": min(weights),
        "maximum_hamming_weight": max(weights),
    }


def _hkdf_related_input_statistics(sample_count: int) -> Dict[str, object]:
    seeds = [
        _derive_seed(_PASSWORD, f"{_SALT_PREFIX}{index}", _PEPPER)
        for index in range(sample_count + 1)
    ]
    adjacent_delta_matches = sum(
        right == left + 1 for left, right in zip(seeds, seeds[1:])
    )
    hamming_distances = [
        _popcount(left ^ right) for left, right in zip(seeds, seeds[1:])
    ]
    return {
        "pairs": sample_count,
        "adjacent_seed_plus_one_matches": adjacent_delta_matches,
        "mean_adjacent_seed_hamming_distance": statistics.mean(hamming_distances),
        "minimum_adjacent_seed_hamming_distance": min(hamming_distances),
        "maximum_adjacent_seed_hamming_distance": max(hamming_distances),
    }


def _benchmark_kdf(sample_count: int) -> Dict[str, object]:
    for index in range(2):
        derive_key(_PASSWORD, f"{_SALT_PREFIX}warmup-{index}", _PEPPER)
    timings: List[float] = []
    for index in range(sample_count):
        start = time.perf_counter()
        derive_key(_PASSWORD, f"{_SALT_PREFIX}benchmark-{index}", _PEPPER)
        timings.append((time.perf_counter() - start) * 1000.0)
    mean_ms = statistics.mean(timings)
    return {
        "samples": sample_count,
        "mean_ms": mean_ms,
        "median_ms": statistics.median(timings),
        "minimum_ms": min(timings),
        "maximum_ms": max(timings),
        "estimated_candidates_per_second": 1000.0 / mean_ms,
    }


def _format_matrix(plaintext: str) -> List[Dict[str, object]]:
    """Round-trip the same plaintext through every public payload variant."""

    cases = (
        {
            "name": "default-aes",
            "api": "encrypt/decrypt",
            "cipher_mode": CipherMode.AES_GCM,
            "replay_protection": False,
            "high_performance": False,
        },
        {
            "name": "default-chacha",
            "api": "encrypt/decrypt",
            "cipher_mode": CipherMode.CHACHA20_POLY1305,
            "replay_protection": False,
            "high_performance": False,
        },
        {
            "name": "replay-aes",
            "api": "CryptoContext",
            "cipher_mode": CipherMode.AES_GCM,
            "replay_protection": True,
            "high_performance": False,
        },
        {
            "name": "replay-chacha",
            "api": "CryptoContext",
            "cipher_mode": CipherMode.CHACHA20_POLY1305,
            "replay_protection": True,
            "high_performance": False,
        },
        {
            "name": "session-aes-no-replay",
            "api": "CryptoContext",
            "cipher_mode": CipherMode.AES_GCM,
            "replay_protection": False,
            "high_performance": True,
        },
        {
            "name": "session-aes-replay",
            "api": "CryptoContext",
            "cipher_mode": CipherMode.AES_GCM,
            "replay_protection": True,
            "high_performance": True,
        },
        {
            "name": "session-chacha-no-replay",
            "api": "CryptoContext",
            "cipher_mode": CipherMode.CHACHA20_POLY1305,
            "replay_protection": False,
            "high_performance": True,
        },
        {
            "name": "session-chacha-replay",
            "api": "CryptoContext",
            "cipher_mode": CipherMode.CHACHA20_POLY1305,
            "replay_protection": True,
            "high_performance": True,
        },
    )
    results: List[Dict[str, object]] = []
    for case in cases:
        mode = cast(CipherMode, case["cipher_mode"])
        replay_protection = bool(case["replay_protection"])
        high_performance = bool(case["high_performance"])
        if case["api"] == "encrypt/decrypt":
            ciphertext = encrypt(
                plaintext,
                _PASSWORD,
                _SALT_PREFIX + "format-matrix",
                _PEPPER,
                cipher_mode=mode,
            )
            recovered = decrypt(
                ciphertext,
                _PASSWORD,
                _SALT_PREFIX + "format-matrix",
                _PEPPER,
            )
        else:
            context = CryptoContext(
                _PASSWORD,
                _SALT_PREFIX + "format-matrix",
                _PEPPER,
                replay_protection=replay_protection,
                high_performance=high_performance,
                cipher_mode=mode,
                session_id=_SESSION_ID if high_performance else None,
                direction="format-matrix",
            )
            ciphertext = context.encrypt(
                plaintext,
                sequence_number=1 if (replay_protection or high_performance) else None,
                aad=_FORMAT_AAD,
            )
            recovered = context.decrypt(ciphertext, aad=_FORMAT_AAD)
        results.append(
            {
                "name": case["name"],
                "api": case["api"],
                "wire_format": ciphertext[:3].decode("ascii"),
                "cipher_mode": mode.value,
                "replay_protection": replay_protection,
                "high_performance": high_performance,
                "plaintext_bytes": len(plaintext.encode("utf-8")),
                "ciphertext_bytes": len(ciphertext),
                "overhead_bytes": len(ciphertext) - len(plaintext.encode("utf-8")),
                "round_trip": recovered == plaintext,
            }
        )
    return results


def run_analysis(sample_count: int, benchmark_samples: int) -> Dict[str, object]:
    plaintext = Path(__file__).resolve().parents[1].joinpath("README.md").read_text(
        encoding="utf-8"
    )
    random_source = random.Random(_ANALYSIS_SEED)
    seeds = [random_source.getrandbits(256) for _ in range(sample_count)]
    outputs = [_g(seed, DEFAULT_PRIME) for seed in seeds]
    identity_offsets = (1, 2, 3, 7, 31, 128)
    identity_results = {
        str(offset): all(
            _related_output_identity(seed, DEFAULT_PRIME, offset)
            for seed in seeds[: min(sample_count, 32)]
        )
        for offset in identity_offsets
    }
    return {
        "analysis_seed": _ANALYSIS_SEED,
        "gmpy2_enabled": _HAS_GMPY2,
        "sample_count": sample_count,
        "default_prime": DEFAULT_PRIME,
        "iteration_count": 128,
        "small_prime_collision_results": _small_prime_results(),
        "large_prime_output_statistics": _bit_statistics(outputs),
        "large_prime_differential_statistics": [
            _differential_statistics(seeds[: min(sample_count, 128)], DEFAULT_PRIME, offset)
            for offset in (1, 2, 3, 7, 31)
        ],
        "related_output_identity_verified": identity_results,
        "hkdf_related_input_statistics": _hkdf_related_input_statistics(sample_count),
        "known_pepper_kdf_benchmark": _benchmark_kdf(benchmark_samples),
        "format_matrix": _format_matrix(plaintext),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=4096)
    parser.add_argument("--benchmark-samples", type=int, default=7)
    args = parser.parse_args()
    if args.samples < 32 or args.benchmark_samples < 3:
        raise SystemExit("samples must be >= 32 and benchmark-samples must be >= 3")
    print(json.dumps(run_analysis(args.samples, args.benchmark_samples), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
