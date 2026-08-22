from fibcrypt.fib import fibonacci_mod


def test_fibonacci_mod_known_values() -> None:
    expected = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]

    assert [fibonacci_mod(index, 65537) for index in range(10)] == expected


def test_fibonacci_mod_applies_modulus() -> None:
    assert fibonacci_mod(100, 10) == 5
