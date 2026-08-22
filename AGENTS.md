# Agent Notes

- This is a single Python package, not a workspace: library code is under `fibcrypt/`, the only executable smoke test is `test/main.py`, and packaging metadata is in `setup.py`.
- Use Python `>=3.8`; install development dependencies with `python3 -m pip install -r requirements-dev.txt`. The `pycryptodomex` dependency is imported through the `Cryptodome` namespace.
- Run `python3 -m pytest` for the focused tests, `ruff check .` for linting, and `mypy` for typechecking. Pytest discovers tests under `tests/` from `pyproject.toml`.
- Run the legacy smoke test from the repository root with `PYTHONPATH=. python3 test/main.py`; the `PYTHONPATH` is needed because the script lives under `test/`. It exercises `encrypt` followed by `decrypt` and prints timing output.
- The main call flow is `fibcrypt.crypto_utils.encrypt/decrypt` -> `fibcrypt.kdf.derive_key` -> `fibcrypt.fib.fibonacci_mod` and `fibcrypt.utils.hash_to_int`; keep changes to these interfaces coordinated.
- `derive_key` uses the full SHA-256-derived seed; do not reintroduce a small modulo reduction because it creates a directly enumerable key space.
- `encrypt` and `decrypt` require the same secret pepper; keep it outside the ciphertext and deployment source control.
- Default AES-GCM payloads returned by `encrypt` use the versioned `FC3 + random_salt + nonce + ciphertext + GCM tag` format; opt-in replay protection uses authenticated `FC4` sequence numbers, while `decrypt` retains authenticated `FC2` migration support.
- `CryptoContext(high_performance=True)` is the opt-in session mode: AES uses `FC7`, ChaCha20 uses `FC8`, and the Fibonacci session key is derived once per session. Keep session IDs and directions unique per traffic direction.
- Build/package changes should be checked against `setup.py`, which now declares version `1.2.0`, runtime dependency `pycryptodomex>=3.22.0`, Python `>=3.8`, and a 256-bit default KDF prime in `fibcrypt.kdf`.
- For PyPI uploads, use the repository-root `.pypirc` explicitly: `.venv/bin/twine upload --config-file .pypirc --repository pypi <artifacts>`; do not rely on the user-level Twine configuration.
