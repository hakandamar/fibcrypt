"""Run a dependency-free subset of NIST SP 800-22 tests on KDF output.

This is an exploratory statistical test harness, not the NIST STS reference
implementation. It deliberately keeps the test data generation and p-value
calculations visible so the results can be reproduced and reviewed.
"""

import argparse
import math
import statistics
from typing import Callable, List, Tuple

from fibcrypt.kdf import DEFAULT_PRIME, derive_key

_BITS_PER_KEY = 256
_MINIMUM_BITS = 1_000_000
_MIN_P_VALUE = 0.01
_PEPPER = "nist-statistical-test-pepper-with-at-least-32-bytes"


def _regularized_gamma_q(a: float, x: float) -> float:
    """Return the regularized upper incomplete gamma function Q(a, x)."""
    if x < 0 or a <= 0:
        raise ValueError("invalid incomplete gamma arguments")
    if x == 0:
        return 1.0
    if x < a + 1.0:
        term = 1.0 / a
        total = term
        for index in range(1, 1000):
            term *= x / (a + index)
            total += term
            if abs(term) <= abs(total) * 1e-15:
                break
        return 1.0 - total * math.exp(-x + a * math.log(x) - math.lgamma(a))

    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for index in range(1, 1000):
        an = -index * (index - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) <= 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def _chi_square_p_value(chi_square: float, degrees_of_freedom: int) -> float:
    return _regularized_gamma_q(degrees_of_freedom / 2.0, chi_square / 2.0)


def _frequency(bits: str) -> float:
    score = abs(sum(1 if bit == "1" else -1 for bit in bits)) / math.sqrt(len(bits))
    return math.erfc(score / math.sqrt(2.0))


def _block_frequency(bits: str, block_size: int = 128) -> float:
    blocks = [bits[index : index + block_size] for index in range(0, len(bits), block_size)]
    proportions = [block.count("1") / block_size for block in blocks if len(block) == block_size]
    chi_square = 4.0 * block_size * sum((proportion - 0.5) ** 2 for proportion in proportions)
    return _chi_square_p_value(chi_square, len(proportions))


def _runs(bits: str) -> float:
    n = len(bits)
    proportion = bits.count("1") / n
    if abs(proportion - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0
    runs = 1 + sum(bits[index] != bits[index - 1] for index in range(1, n))
    numerator = abs(runs - 2.0 * n * proportion * (1.0 - proportion))
    denominator = 2.0 * math.sqrt(2.0 * n) * proportion * (1.0 - proportion)
    return math.erfc(numerator / denominator)


def _longest_run(bits: str, block_size: int = 8) -> float:
    probabilities = (0.2148, 0.3672, 0.2305, 0.1875)
    counts = [0, 0, 0, 0]
    blocks = len(bits) // block_size
    for index in range(blocks):
        block = bits[index * block_size : (index + 1) * block_size]
        longest = max(len(run) for run in block.replace("0", " ").split()) if "1" in block else 0
        category = 0 if longest <= 1 else 1 if longest == 2 else 2 if longest == 3 else 3
        counts[category] += 1
    chi_square = sum(
        (count - blocks * probability) ** 2 / (blocks * probability)
        for count, probability in zip(counts, probabilities)
    )
    return _chi_square_p_value(chi_square, 3)


def _psi(bits: str, order: int) -> float:
    extended = bits + bits[: order - 1]
    counts = [0] * (2**order)
    for index in range(len(bits)):
        counts[int(extended[index : index + order], 2)] += 1
    return (2**order / len(bits)) * sum(count * count for count in counts) - len(bits)


def _serial(bits: str) -> float:
    psi_1 = _psi(bits, 1)
    psi_2 = _psi(bits, 2)
    delta_1 = max(psi_2 - psi_1, 0.0)
    delta_2 = max(psi_2 - 2.0 * psi_1, 0.0)
    return min(
        _chi_square_p_value(delta_1, 2),
        _chi_square_p_value(delta_2, 1),
    )


def _approximate_entropy(bits: str) -> float:
    def phi(order: int) -> float:
        extended = bits + bits[: order - 1]
        counts = [0] * (2**order)
        for index in range(len(bits)):
            counts[int(extended[index : index + order], 2)] += 1
        return sum(
            (count / len(bits)) * math.log(count / len(bits))
            for count in counts
            if count
        )

    approximate_entropy = phi(2) - phi(3)
    chi_square = 2.0 * len(bits) * (math.log(2.0) - approximate_entropy)
    return _chi_square_p_value(chi_square, 2)


def _cumulative_sums(bits: str) -> float:
    values = [1 if bit == "1" else -1 for bit in bits]
    running_total = 0
    forward = 0
    for value in values:
        running_total += value
        forward = max(forward, abs(running_total))
    running_total = 0
    backward = 0
    for value in reversed(values):
        running_total += value
        backward = max(backward, abs(running_total))
    z = max(forward, backward)
    return math.erfc(z / math.sqrt(2.0 * len(bits)))


def _generate_bits(sequence: int, iterations: int) -> str:
    chunks: List[str] = []
    key_count = math.ceil(_MINIMUM_BITS / _BITS_PER_KEY)
    for index in range(key_count):
        key = derive_key(
            f"nist-password-{sequence}",
            f"nist-salt-{sequence}-{index}",
            _PEPPER,
            iterations=iterations,
            prime=DEFAULT_PRIME,
        )
        chunks.append(f"{key:0{_BITS_PER_KEY}b}")
    return "".join(chunks)[:_MINIMUM_BITS]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sequences", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=128)
    args = parser.parse_args()

    tests: Tuple[Tuple[str, Callable[[str], float]], ...] = (
        ("Frequency (Monobit)", _frequency),
        ("Frequency (Block)", _block_frequency),
        ("Runs", _runs),
        ("Longest Run of Ones", _longest_run),
        ("Serial", _serial),
        ("Approximate Entropy", _approximate_entropy),
        ("Cumulative Sums", _cumulative_sums),
    )
    results = {name: [] for name, _ in tests}
    for sequence in range(args.sequences):
        bits = _generate_bits(sequence, args.iterations)
        for name, test in tests:
            results[name].append(test(bits))

    print(f"SP 800-22 exploratory run: sequences={args.sequences}, bits={_MINIMUM_BITS}")
    print(f"Pass threshold: p >= {_MIN_P_VALUE}")
    for name, values in results.items():
        formatted_values = ", ".join(f"{value:.6f}" for value in values)
        print(f"{name}: p={statistics.mean(values):.6f} [{formatted_values}]")


if __name__ == "__main__":
    main()
