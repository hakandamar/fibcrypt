from typing import Tuple

try:
    import gmpy2
    _HAS_GMPY2 = True
except ImportError:
    _HAS_GMPY2 = False


def _fibonacci_pair_python(n: int, mod: int) -> Tuple[int, int]:
    """Return (F(n), F(n + 1)) modulo ``mod`` using fast doubling (pure Python)."""
    if n == 0:
        return 0, 1

    a, b = _fibonacci_pair_python(n // 2, mod)
    c = (a * ((2 * b - a) % mod)) % mod
    d = (a * a + b * b) % mod

    if n % 2 == 0:
        return c, d
    return d, (c + d) % mod


def _fibonacci_pair_gmpy2(n: int, mod: int) -> Tuple[int, int]:
    """Return (F(n), F(n + 1)) modulo ``mod`` using fast doubling (gmpy2 accelerated)."""
    if n == 0:
        return gmpy2.mpz(0), gmpy2.mpz(1)

    a, b = _fibonacci_pair_gmpy2(n // 2, mod)
    two_b_minus_a = (2 * b - a) % mod
    c = (a * two_b_minus_a) % mod
    d = (a * a + b * b) % mod

    if n % 2 == 0:
        return c, d
    return d, (c + d) % mod


if _HAS_GMPY2:
    def fibonacci_pair(n: int, mod: int) -> Tuple[int, int]:
        """Return (F(n), F(n + 1)) modulo ``mod`` using fast doubling."""
        mod_mpz = gmpy2.mpz(mod)
        n_mpz = gmpy2.mpz(n)
        a, b = _fibonacci_pair_gmpy2(n_mpz, mod_mpz)
        return int(a), int(b)
else:
    def fibonacci_pair(n: int, mod: int) -> Tuple[int, int]:
        """Return (F(n), F(n + 1)) modulo ``mod`` using fast doubling."""
        return _fibonacci_pair_python(n, mod)


def fibonacci_mod(n: int, mod: int) -> int:
    """Compute the nth Fibonacci number modulo ``mod`` in O(log n) time."""
    return fibonacci_pair(n, mod)[0]