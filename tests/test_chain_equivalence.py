import random
from typing import Tuple

import pytest

from fibcrypt.fib import (
    fibonacci_mod,
    fibonacci_pair,
    fibonacci_pair_iter,
    fibonacci_xor_chain,
)
from fibcrypt.kdf import DEFAULT_PRIME, _derive_seed, derive_key

PEPPER = "TEST_ONLY-chain-pepper-with-at-least-32-bytes"


def _reference_chain(start: int, count: int, mod: int) -> int:
    result = 0
    for index in range(count):
        result ^= fibonacci_mod(start + index, mod)
    return result


@pytest.mark.parametrize("start", [0, 1, 42, 2**256 - 1])
@pytest.mark.parametrize("count", [1, 2, 7, 32, 128, 129])
@pytest.mark.parametrize("mod", [DEFAULT_PRIME, 2**61 - 1, 2**32 - 5, 1, 2, 3, 5, 17])
def test_chain_matches_independent_fibonacci_reference(
    start: int, count: int, mod: int
) -> None:
    assert fibonacci_xor_chain(start, count, mod) == _reference_chain(start, count, mod)


def test_chain_matches_reference_for_deterministic_large_starts() -> None:
    rng = random.Random(0xF1BC121)
    cases = [(rng.randrange(2**260), rng.randrange(1, 130)) for _ in range(50)]

    for start, count in cases:
        assert fibonacci_xor_chain(start, count, DEFAULT_PRIME) == _reference_chain(
            start, count, DEFAULT_PRIME
        )


@pytest.mark.parametrize("n", [0, 1, 2, 42, 2**260 - 1])
@pytest.mark.parametrize("mod", [DEFAULT_PRIME, 2**61 - 1, 2**32 - 5, 17])
def test_iterative_pair_matches_public_pair(n: int, mod: int) -> None:
    assert fibonacci_pair_iter(n, mod) == fibonacci_pair(n, mod)


def test_iterative_pair_and_chain_reduce_modulus_one() -> None:
    assert fibonacci_pair_iter(0, 1) == (0, 0)
    assert fibonacci_xor_chain(0, 2, 1) == 0


@pytest.mark.parametrize(
    "func, args",
    [
        (fibonacci_pair_iter, (-1, DEFAULT_PRIME)),
        (fibonacci_pair_iter, (0, 0)),
        (fibonacci_pair_iter, (None, DEFAULT_PRIME)),  # type: ignore[arg-type]
        (fibonacci_pair_iter, (0, None)),  # type: ignore[arg-type]
        (fibonacci_xor_chain, (-1, 1, DEFAULT_PRIME)),
        (fibonacci_xor_chain, (0, 0, DEFAULT_PRIME)),
        (fibonacci_xor_chain, (0, True, DEFAULT_PRIME)),
        (fibonacci_xor_chain, (0, 1, 0)),
        (fibonacci_xor_chain, (None, 1, DEFAULT_PRIME)),  # type: ignore[arg-type]
        (fibonacci_xor_chain, (0, 1, None)),  # type: ignore[arg-type]
    ],
)
def test_new_fibonacci_helpers_reject_invalid_arguments(
    func: object, args: Tuple[object, ...]
) -> None:
    with pytest.raises(ValueError):
        func(*args)  # type: ignore[operator]


@pytest.mark.parametrize("iterations", [1, 2, 7, 128, 129, 2048])
@pytest.mark.parametrize(
    "password, salt, prime",
    [
        ("password", "salt", DEFAULT_PRIME),
        ("şifre\0🔐", "salt\0context", 2**61 - 1),
        ("custom", "prime", 2**32 - 5),
    ],
)
def test_derive_key_matches_pre_optimization_reference(
    iterations: int, password: str, salt: str, prime: int
) -> None:
    seed = _derive_seed(password, salt, PEPPER)
    expected = _reference_chain(seed, iterations, prime)

    assert derive_key(password, salt, PEPPER, iterations, prime) == expected
