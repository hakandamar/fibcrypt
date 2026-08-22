from typing import Tuple


def fibonacci_pair(n: int, mod: int) -> Tuple[int, int]:
    """Return (F(n), F(n + 1)) modulo ``mod`` using fast doubling."""
    if n == 0:
        return 0, 1

    a, b = fibonacci_pair(n // 2, mod)
    c = (a * ((2 * b - a) % mod)) % mod
    d = (a * a + b * b) % mod

    if n % 2 == 0:
        return c, d
    return d, (c + d) % mod


def fibonacci_mod(n: int, mod: int) -> int:
    """Compute the nth Fibonacci number modulo ``mod`` in O(log n) time."""
    return fibonacci_pair(n, mod)[0]
