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
        if n < 0:
            raise ValueError("n must be non-negative")
        if mod <= 0:
            raise ValueError("mod must be positive")
        mod_mpz = gmpy2.mpz(mod)
        n_mpz = gmpy2.mpz(n)
        a, b = _fibonacci_pair_gmpy2(n_mpz, mod_mpz)
        return int(a), int(b)
else:
    def fibonacci_pair(n: int, mod: int) -> Tuple[int, int]:
        """Return (F(n), F(n + 1)) modulo ``mod`` using fast doubling."""
        if n < 0:
            raise ValueError("n must be non-negative")
        if mod <= 0:
            raise ValueError("mod must be positive")
        return _fibonacci_pair_python(n, mod)


def fibonacci_mod(n: int, mod: int) -> int:
    """Compute the nth Fibonacci number modulo ``mod`` in O(log n) time."""
    return fibonacci_pair(n, mod)[0]


def fibonacci_pair_iter(n: int, mod: int) -> Tuple[int, int]:
    """Return ``(F(n), F(n + 1))`` modulo ``mod`` using iterative fast doubling.

    This non-recursive implementation is the one-pass seed for
    :func:`fibonacci_xor_chain`.  It intentionally uses Python integers so the
    chain has the same behavior whether or not the optional ``gmpy2`` module is
    installed.
    """

    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValueError("n must be a non-negative integer")
    if not isinstance(mod, int) or isinstance(mod, bool) or mod <= 0:
        raise ValueError("mod must be a positive integer")

    a, b = 0, 1
    for bit in bin(n)[2:]:
        c = (a * ((b << 1) - a)) % mod
        d = (a * a + b * b) % mod
        if bit == "0":
            a, b = c, d
        else:
            a, b = d, (c + d) % mod
    return a, b


def fibonacci_xor_chain(start: int, count: int, mod: int) -> int:
    """XOR consecutive Fibonacci values reduced modulo ``mod``.

    The result is bit-identical to independently evaluating
    ``fibonacci_mod(start + i, mod)`` for every ``i``.  One fast-doubling pass
    initializes the pair, and each following value requires only a modular
    addition.
    """

    if not isinstance(start, int) or isinstance(start, bool) or start < 0:
        raise ValueError("start must be a non-negative integer")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ValueError("count must be a positive integer")
    if not isinstance(mod, int) or isinstance(mod, bool) or mod <= 0:
        raise ValueError("mod must be a positive integer")

    key = 0
    f, next_f = fibonacci_pair_iter(start, mod)
    for _ in range(count):
        key ^= f
        f, next_f = next_f, (f + next_f) % mod
    return int(key)
