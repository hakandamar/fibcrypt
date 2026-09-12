# fibcrypt

[![PyPI version](https://img.shields.io/pypi/v/fibcrypt.svg)](https://pypi.org/project/fibcrypt/)
[![Python versions](https://img.shields.io/pypi/pyversions/fibcrypt.svg)](https://pypi.org/project/fibcrypt/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/fibcrypt?period=total&units=INTERNATIONAL_SYSTEM&left_color=RED&right_color=BLUE&left_text=Downloads)](https://pepy.tech/projects/fibcrypt)
[![CI](https://github.com/hakandamar/fibcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/hakandamar/fibcrypt/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/fibcrypt.svg)](LICENSE)

**Latest version:** `v1.2.1` · **Tests:** `309 passed` · **Coverage:** `96%`

`fibcrypt` is an open-source, edge-oriented encryption toolkit that combines a Fibonacci-based key derivation design
with authenticated encryption.

It is designed for applications that need many low-latency encryption/decryption operations and want to evaluate an
alternative, transparent cryptographic construction. It is **experimental cryptographic software**, not a replacement
for Argon2, scrypt, or other independently reviewed password KDFs.

## Table of Contents

- [Project Status](#project-status)
- [Articles](#articles)
- [What It Provides](#what-it-provides)
- [Security Model](#security-model)
  - [Optional Replay Protection](#optional-replay-protection)
  - [Opt-In High-Performance Session Mode](#opt-in-high-performance-session-mode)
- [Installation](#installation)
- [Usage](#usage)
  - [Using ChaCha20-Poly1305 (for non-AES-NI edge devices)](#using-chacha20-poly1305-for-non-aes-ni-edge-devices)
  - [Using CryptoContext for Repeated Decryptions (Key Caching)](#using-cryptocontext-for-repeated-decryptions-key-caching)
- [Parameters](#parameters)
- [KDF Comparison](#kdf-comparison)
- [Performance](#performance)
  - [v1.2.1 KDF chain benchmark](#v121-kdf-chain-benchmark)
  - [v1.2.0 vs v1.2.1 Performance Benchmark](#v120-v121-performance-benchmark)
  - [v1.1.2 vs v1.2.0 High-Performance Session Benchmark](#v112-v120-high-performance-session-benchmark)
- [Security Improvements](#security-improvements)
- [Statistical Testing](#statistical-testing)
- [Upgrading From 0.1.5](UPGRADING_FROM_0_1_5.md)
- [Development](#development)
- [Security](#security)
- [License](#license)

## Project Status

The project is maintained as an experimental, independently unaudited cryptographic toolkit. The public API and wire
formats may evolve between minor releases. Review the [security policy](SECURITY.md) before using the package in a
production or regulated environment. See [CHANGELOG.md](CHANGELOG.md) for release history.

## Articles

- [Part 2 (2026): fibcrypt v1.0 Stable - Authenticated Fibonacci-Based Encryption for Edge Workloads](https://hakandamar.com/fibcrypt-v1-0-stable-authenticated-fibonacci-based-encryption-for-edge-workloads-41cb9650512e)
- [Part 1 (2025): A Lightweight Cryptographic Toolkit Based on Fibonacci Matrix Exponentiation](https://hakandamar.com/a-lightweight-cryptographic-toolkit-based-on-fibonacci-matrix-exponentiation-fibcrypt-484a9cf0a0a1)

## What It Provides

- Fibonacci-based key derivation using modular fast-doubling arithmetic
- A 256-bit default modulus and full SHA-256-derived seed
- **HKDF-based pepper mixing** for improved domain separation
- AES-256-GCM authenticated encryption in the current `FC3` format
- **ChaCha20-Poly1305** AEAD support (`FC5`/`FC6` formats) for non-AES-NI edge platforms
- Legacy authenticated `FC2` AES-CBC/HMAC payload decryption for migration
- A fresh random salt and nonce for every encryption
- A required deployment secret (`pepper`) kept outside the ciphertext
- Versioned `FC3` ciphertext payloads by default
- Optional `FC4` sequence-number binding and in-process replay protection
- Opt-in `FC7`/`FC8` session mode for high-throughput traffic
- **Thread-safe bounded key caching** in `CryptoContext` for repeated decryptions
- **Optional `gmpy2` acceleration** (the v1.2.1 chain is correct without it; any
  remaining benefit is a platform-dependent micro-optimization)

## Security Model

Each encryption requires four inputs:

- `plaintext`: the data to encrypt
- `password`: the user/application password
- `salt`: caller-provided context; it may be public, but must be supplied again for decryption
- `pepper`: a secret deployment value that must not be stored in the ciphertext or source code

The pepper must contain at least 32 UTF-8 bytes. This is a minimum deployment-secret requirement, not a substitute for
choosing a strong password.

The ciphertext contains the version marker, random salt, nonce, encrypted data, and authentication tag:

```text
FC3 + random_salt + nonce + ciphertext + GCM tag
```

**ChaCha20-Poly1305 format:**
```text
FC5 + random_salt + nonce + ciphertext + tag
```

**Replay-protected formats (`FC4`/`FC6`):**
```text
FC4/FC6 + sequence_number + random_salt + nonce + ciphertext + tag
```

**High-performance session formats (`FC7`/`FC8`):**
```text
FC7/FC8 + session_id + sequence_number + ciphertext + tag
```

The high-performance nonce is derived from the session sequence number and is not stored separately in the payload. The
session key is derived once per session instead of once per message.

Decryption authenticates the tag before returning plaintext. Modified or truncated ciphertexts, wrong passwords, wrong
salts, and wrong peppers are rejected.

### Optional Replay Protection

Replay protection is disabled by default, so the existing `encrypt()` and `decrypt()` API continues to use the stateless
`FC3` format. Applications that process ordered control or telemetry messages can opt in through `CryptoContext`:

```python
from fibcrypt.crypto_utils import CryptoContext

sender = CryptoContext(password, salt, pepper, replay_protection=True)
receiver = CryptoContext(password, salt, pepper, replay_protection=True)

ciphertext = sender.encrypt(message, sequence_number=42, aad=b"device-7/telemetry")
plaintext = receiver.decrypt(ciphertext, aad=b"device-7/telemetry")
```

When enabled, `sequence_number` is required and new payloads use the `FC4` (AES-GCM) or `FC6` (ChaCha20) format. The
sequence number is authenticated by the AEAD cipher and the receiver uses a thread-safe sliding replay window. Duplicate
or sufficiently old sequence numbers are rejected. `aad` can bind a message to a device, channel, or message type, but
must be supplied identically during decryption.

The in-process replay window does not coordinate multiple application instances. Distributed deployments must provide
shared atomic replay state at the application or infrastructure layer.

### Opt-In High-Performance Session Mode

`high_performance=True` is disabled by default. It changes the `CryptoContext` payload format to `FC7` for AES-GCM or
`FC8` for ChaCha20-Poly1305 and derives the Fibonacci session key once instead of deriving a key for every message:

```python
import os

from fibcrypt.crypto_utils import CryptoContext

session_id = os.urandom(16)
sender = CryptoContext(
    password,
    salt,
    pepper,
    replay_protection=True,
    high_performance=True,
    session_id=session_id,
    direction="uplink",
)
receiver = CryptoContext(
    password,
    salt,
    pepper,
    replay_protection=True,
    high_performance=True,
    session_id=session_id,
    direction="uplink",
)

ciphertext = sender.encrypt(message, sequence_number=1, aad=b"base-station")
plaintext = receiver.decrypt(ciphertext, aad=b"base-station")
```

`sequence_number` is required in high-performance mode even when replay protection is disabled because it provides the
per-message AEAD nonce. A sequence number must never be reused with the same session ID and direction. Use distinct
session IDs or directions for uplink and downlink traffic. The `session_id` must be explicitly shared with both
endpoints; this prevents an attacker from forcing a receiver to derive unbounded numbers of session keys.
High-performance contexts reject the default `FC3`/`FC5` and replay `FC4`/`FC6` payloads so that a deployment cannot
silently fall back to per-message KDF.

For a ciphertext-only attacker who has no password, caller salt, or pepper, the payload and public source code are not
sufficient to derive the keys. This assumes the deployment pepper is a high-entropy secret and is not embedded in
application source, test configuration, logs, or the payload.

Important limitations:

- The Fibonacci KDF is custom and has not received an independent cryptographic audit.
- `iterations=128` is selected for latency, not as a claim of equivalence to a memory-hard password KDF. It remains the
  compatibility default; new deployments should use `iterations=2048` on both endpoints.
- Weak or reused passwords remain vulnerable to dictionary attacks if the attacker also knows or can guess the salt and
  obtains the pepper.
- The pepper must be managed as a deployment secret and contain at least 32 bytes. If an attacker compromises the
  application host and reads its secrets, this model no longer applies.
- Do not use this package for high-assurance or regulated cryptographic requirements without an independent review.

## Installation

```bash
pip install fibcrypt
```

**Optional: gmpy2 acceleration** (not required by the v1.2.1 chain):

```bash
pip install fibcrypt[gmpy2]
# It may provide a small, platform-dependent micro-gain.
# or
pip install gmpy2
```

## Usage

Set the pepper through a secret manager or environment variable. Do not commit it to source control. In production, keep
the pepper in a secure secret-management service such as Azure Key Vault; for high-assurance deployments, an HSM v3
backing with FIPS 140-3 Level 3 certification is recommended.

```bash
export FIBCRYPT_PEPPER="your-long-random-deployment-secret"
```

```python
import os

from fibcrypt.crypto_utils import decrypt, encrypt, CryptoContext, CipherMode

message = "This is a secret message"
password = "my-strong-password"
salt = "application-context"
pepper = os.environ["FIBCRYPT_PEPPER"]

# Default: AES-256-GCM (FC3 format)
ciphertext = encrypt(message, password, salt, pepper)
print("Encrypted:", ciphertext.hex())

plaintext = decrypt(ciphertext, password, salt, pepper)
print("Decrypted:", plaintext)
```

`encrypt` returns `bytes`. Store or transmit those bytes directly, or encode them as hexadecimal/base64. Keep the `salt`
and `pepper` available to the decrypting service; only the pepper must remain secret.

Wrong credentials and tampered ciphertext raise `ValueError` during authentication.

### Using ChaCha20-Poly1305 (for non-AES-NI edge devices)

```python
# ChaCha20-Poly1305 AEAD (FC5 format)
ciphertext = encrypt(message, password, salt, pepper, cipher_mode=CipherMode.CHACHA20_POLY1305)
plaintext = decrypt(ciphertext, password, salt, pepper)
```

### Using CryptoContext for Repeated Decryptions (Key Caching)

```python
# Keeps context configuration together and caches repeated decryptions
ctx = CryptoContext(password, salt, pepper)

# Encryption still uses a fresh random salt and derives a per-payload key
ct = ctx.encrypt("message")

# Repeated decryption of the same payload reuses the bounded cache
pt1 = ctx.decrypt(ct)
pt2 = ctx.decrypt(ct)

# With replay protection
ctx_rp = CryptoContext(password, salt, pepper, replay_protection=True)
ct = ctx_rp.encrypt("telemetry", sequence_number=1, aad=b"device-7")
pt = ctx_rp.decrypt(ct, aad=b"device-7")
```

## Parameters

The default public API uses:

- `iterations=128`
- `prime=2**256 - 2**32 - 977`
- `cipher_mode=CipherMode.AES_GCM`
- `CryptoContext.high_performance=False`

Both `iterations` and `prime` can be overridden explicitly for experiments and benchmarks. `iterations` must be positive
and `prime` must be greater than one. Changing these values changes the derived keys, so the parameters must remain
consistent between encryption and decryption. Keep `128` for existing deployments; for a new deployment, configure both
endpoints with `iterations=2048`.

## KDF Comparison

Fibcrypt, Argon2id, and scrypt solve related but different engineering problems. The table compares the constructions
as password-based key derivation functions, not the complete encryption protocols around them.

| Property | Fibcrypt | Argon2id | scrypt |
| --- | --- | --- | --- |
| Primary design | Low-latency key derivation integrated with authenticated encryption and optional sessions | Memory-hard password hashing and key derivation | Sequential memory-hard password-based key derivation |
| Core construction | HKDF-SHA-256 seed derivation followed by 128 modular Fibonacci values XORed together | BLAKE2b-based memory-filling function with Argon2i/Argon2d hybrid access pattern | PBKDF2-HMAC-SHA-256 around ROMix and Salsa20/8 |
| Memory cost | Constant and small; no large working memory allocation | Explicitly tunable from MiB-scale to GiB-scale deployments | Tunable through `N`, `r`, and `p`; approximate working memory is `128 * N * r * p` bytes |
| CPU and latency control | `iterations=128`; selected for low latency; session mode derives one key per session | Tunable `t` passes, `m` memory, and `p` lanes | Tunable `N` CPU/memory cost, `r` block size, and `p` parallelism |
| GPU/ASIC cost model | CPU-oriented arithmetic with little memory pressure | Memory bandwidth and capacity are part of the attacker cost | Memory bandwidth and sequential ROMix work are part of the attacker cost |
| Salt and secret input | Caller salt plus per-payload/session context; deployment pepper is required and kept secret | Unique public salt; optional secret value can be supplied by an integration | Unique public salt; a pepper requires an application-level wrapper |
| Output | 256-bit key material consumed by `FC3`-`FC8` authenticated formats | Variable-length tag/key output | Variable-length derived key output |
| Project measurement | v1.2.0 historical baseline: about 17 ms per KDF and 59 known-pepper candidates/second with `gmpy2`; v1.2.1 is platform-dependent and measured by the benchmark script | Not benchmarked in this project; cost depends on `m`, `t`, `p`, and hardware | Not benchmarked in this project; cost depends on `N`, `r`, `p`, and hardware |
| Best fit | Latency-sensitive edge encryption where low memory use and a deployment pepper are acceptable design choices | Password storage and password-derived keys where memory can be deliberately allocated; Argon2id is the standard variant to select | Password-derived keys where a mature memory-hard construction and existing scrypt ecosystem are preferred |
| Main tradeoff | Low memory and low latency, with less attacker-cost leverage from memory hardness | Higher memory and setup cost, requiring per-service resource budgeting | Higher memory and setup cost, with more parameters to tune for the target platform |

For a password-derived key exposed to offline guessing, the practical choice is normally Argon2id or scrypt with
parameters measured on the target system. Fibcrypt occupies a different point in the design space: it prioritizes
low-latency, low-memory operation and uses the deployment pepper as a required secret input. The Fibcrypt measurements
above must not be read as speed comparisons against Argon2id or scrypt because those algorithms were not benchmarked with
matched parameters on the same machine.

Reference specifications: [RFC 9106 (Argon2)](https://www.rfc-editor.org/rfc/rfc9106.html) and
[RFC 7914 (scrypt)](https://www.rfc-editor.org/rfc/rfc7914.html).

## Performance

### v1.2.1 KDF chain benchmark

v1.2.1 computes the consecutive Fibonacci window with one fast-doubling pass and modular additions. The derived key is
bit-for-bit identical to v1.2.0, so no ciphertext or wire-format migration is required. The benchmark is reproducible
with safe synthetic inputs and reports the local platform and optional `gmpy2` status:

```bash
PYTHONPATH=. .venv/bin/python scripts/bench_v1_2_1.py --samples 7 --warmup 1
```

The technical-note reference run was on x86_64 Linux with Python 3.12 and `gmpy2`; its numbers are not guarantees for
other platforms. In that reference, `derive_key(iterations=128)` was about `0.205 ms` and `iterations=2048` about
`0.37 ms`. The latter is approximately 50x lower latency than the old v1.2.0/128 implementation (~19.4 ms), while it
is approximately 1.8x the optimized v1.2.1/128 cost. This is a latency comparison, not a claim that 2048 is 50x
stronger. The chain optimization also accelerates known-pepper offline guessing; measure and choose the work factor
accordingly, and prefer a memory-hard KDF for password storage.

The `gmpy2` dependency is no longer necessary for correctness or for the main v1.2.1 speedup. It remains optional for a
small, platform-dependent micro-gain. In session mode, per-message encryption/decryption remains unchanged; only the
one-time session setup KDF becomes faster.

#### v1.2.1 result by FC format

The following summarizes the v1.2.0 reference measurements and the v1.2.1
chain-optimized results. Values are approximate and hardware-dependent:

| Format / path | v1.2.0 | v1.2.1 | Approx. change |
| --- | ---: | ---: | ---: |
| FC2 legacy | unchanged | unchanged | ~1x |
| FC3 AES encrypt/decrypt | ~19.8 ms | ~0.25–0.30 ms | ~70–79x faster |
| FC4 replay AES | ~19.9 ms | ~0.25–0.30 ms | ~66–80x faster |
| FC5 ChaCha encrypt/decrypt | ~19.8 ms | ~0.24–0.29 ms | ~68–83x faster |
| FC6 replay ChaCha | ~19.9 ms | ~0.25–0.29 ms | ~68–80x faster |
| FC7 session setup | ~16.6–19 ms | ~0.28 ms | ~59–68x faster |
| FC8 session setup | ~16.6–19 ms | ~0.27 ms | ~62–70x faster |
| FC7/FC8 per-message operations | ~0.01–0.04 ms | ~0.01–0.04 ms | Essentially unchanged |

FC2 deliberately keeps its legacy derivation path. FC3–FC6 numbers come from
the x86_64 reference run; current Apple Silicon measurements are recorded in
[`bench_results.md`](bench_results.md).

On the development benchmark machine (Python 3.14, Apple Silicon), the release comparison is:

| Payload | Operation | v1.0.0 | v1.1.2 (pure Python) | v1.1.2 (with gmpy2) |
| --- | --- | ---: | ---: | ---: |
| 16 B | Encrypt | 67.8 ms | 33.097 ms | 16.618 ms |
| 16 B | Decrypt | 68.4 ms | 33.529 ms | 16.693 ms |
| 1 KiB | Encrypt | 68.5 ms | 33.136 ms | 16.518 ms |
| 1 KiB | Decrypt | 69.0 ms | 32.490 ms | 16.562 ms |
| 1 MiB | Encrypt | 73.4 ms | 39.335 ms | 22.765 ms |
| 1 MiB | Decrypt | 72.8 ms | 39.811 ms | 22.975 ms |

All measurements use the default `iterations=128` and 256-bit prime, with seven samples after one warmup. The v1.0.0
values are rounded values recorded in the v1.0.0 distribution metadata; v1.1.2 values were measured on the same Python
3.14/Apple Silicon environment. The v1.1.2 pure-Python column disables gmpy2, while the final column has gmpy2 enabled.

The comparison is performance-oriented, not a wire-format comparison: v1.0.0 uses authenticated `FC2` AES-CBC/HMAC,
while v1.1.2 uses authenticated `FC3` AES-GCM. Relative to v1.0.0, v1.1.2 is approximately 1.8-2.1x faster without gmpy2
and 3.2-4.2x faster with gmpy2.

These are reference measurements, not performance guarantees. Benchmark the target edge hardware before deployment.

### v1.2.0 vs v1.2.1 Performance Benchmark

Both columns below use the same Apple Silicon environment, Python 3.14, `gmpy2`,
explicit session IDs, and replay protection. v1.2.0 values are the existing
reference measurements; v1.2.1 values were remeasured with seven samples after
one warmup. Session setup improved separately from the per-message operations:
approximately `16.6 ms` in v1.2.0 versus `0.27–0.28 ms` in v1.2.1.

| Cipher | Payload | v1.2.0 Encrypt | v1.2.1 Encrypt | Relative | v1.2.0 Decrypt | v1.2.1 Decrypt | Relative |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-GCM / FC7 | 16 B | 0.027 ms | 0.026 ms | 1.04x | 0.031 ms | 0.036 ms | 0.86x |
| AES-GCM / FC7 | 1 KiB | 0.030 ms | 0.031 ms | 0.97x | 0.036 ms | 0.038 ms | 0.95x |
| AES-GCM / FC7 | 1 MiB | 6.207 ms | 6.436 ms | 0.96x | 6.257 ms | 6.639 ms | 0.94x |
| ChaCha20-Poly1305 / FC8 | 16 B | 0.012 ms | 0.013 ms | 0.92x | 0.019 ms | 0.021 ms | 0.90x |
| ChaCha20-Poly1305 / FC8 | 1 KiB | 0.014 ms | 0.014 ms | 1.00x | 0.022 ms | 0.023 ms | 0.96x |
| ChaCha20-Poly1305 / FC8 | 1 MiB | 2.075 ms | 2.278 ms | 0.91x | 2.102 ms | 2.340 ms | 0.90x |

The per-message session path is therefore effectively unchanged; small ratio
differences are normal benchmark noise and payload/AEAD costs. The v1.2.1
benefit is concentrated in the one-time KDF/session setup.

### v1.1.2 vs v1.2.0 High-Performance Session Benchmark

With gmpy2 enabled, explicit session ID, and replay protection, v1.2.0's `CryptoContext(high_performance=True)` derives
the Fibonacci session key once per endpoint. Session setup cost was approximately `16.6 ms` per endpoint. Subsequent
messages use the session key:

| Cipher | Payload | v1.1.2 Encrypt | v1.2.0 Encrypt | Encrypt speedup | v1.1.2 Decrypt | v1.2.0 Decrypt | Decrypt speedup |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AES-GCM / FC7 | 16 B | 16.353 ms | 0.027 ms | 606x | 16.413 ms | 0.031 ms | 529x |
| AES-GCM / FC7 | 1 KiB | 16.518 ms | 0.030 ms | 551x | 16.387 ms | 0.036 ms | 455x |
| AES-GCM / FC7 | 1 MiB | 23.187 ms | 6.207 ms | 3.7x | 22.788 ms | 6.257 ms | 3.6x |
| ChaCha20-Poly1305 / FC8 | 16 B | 16.363 ms | 0.012 ms | 1364x | 16.328 ms | 0.019 ms | 859x |
| ChaCha20-Poly1305 / FC8 | 1 KiB | 16.350 ms | 0.014 ms | 1168x | 16.602 ms | 0.022 ms | 755x |
| ChaCha20-Poly1305 / FC8 | 1 MiB | 18.372 ms | 2.075 ms | 8.9x | 18.282 ms | 2.102 ms | 8.7x |

## Security Improvements

Compared with the original PyPI `fibcrypt 0.1.5` release, `fibcrypt 1.2.0` includes:

- Modular fast-doubling Fibonacci arithmetic instead of unbounded intermediate matrix growth
- A 256-bit default modulus instead of `65537`
- The full SHA-256-derived seed instead of a directly enumerable `seed % 10**6` space
- A required deployment pepper kept outside the ciphertext and source code
- **HKDF-based pepper mixing** for proper key separation
- A fresh random salt for every encryption
- Separate key derivation domains for legacy encryption and authentication
- AES-GCM authenticated encryption instead of a CBC/HMAC composition for new payloads
- **ChaCha20-Poly1305 AEAD** as an alternative cipher mode
- Versioned `FC3`/`FC5` payloads with explicit format boundaries
- Optional `FC4`/`FC6` sequence-number binding and in-process replay protection
- Opt-in `FC7`/`FC8` session-key encryption for high-throughput traffic
- **Thread-safe bounded key caching** in `CryptoContext` for repeated decryptions
- **Optional gmpy2-accelerated Fibonacci arithmetic** with pure Python fallback
- Approximately 174-207x lower measured latency than the published `0.1.5` artifact on the benchmark machine

## Statistical Testing

An exploratory run of selected NIST SP 800-22 tests was performed against one 1,000,000-bit stream generated from the
current KDF using the default `iterations=128` and 256-bit prime:

| Test | p-value |
| --- | ---: |
| Frequency (Monobit) | 0.586441 |
| Frequency (Block) | 0.412220 |
| Runs | 0.969452 |
| Longest Run of Ones | 0.063463 |
| Serial | 0.861900 |
| Approximate Entropy | 0.141916 |
| Cumulative Sums | 0.344659 |

All observed p-values exceeded the exploratory threshold of `0.01`. These results indicate no obvious statistical
anomaly in this sample. They do not prove cryptographic randomness, establish KDF security, or replace the full NIST
Statistical Test Suite, multiple independent sequences, or an independent cryptographic audit. The reproducible,
dependency-free harness is available at `scripts/nist_sp800_22.py`.

For a broader implementation-level review of the Fibonacci KDF, see [`CRYPTO_KDF_ANALYSIS.md`](CRYPTO_KDF_ANALYSIS.md).
It records related-output identities, small-prime collision experiments, default-modulus output checks, HKDF
related-input tests, known-pepper timing measurements, and a complete public format matrix covering `FC3` through `FC8`
across AES-GCM, ChaCha20-Poly1305, replay protection, and high-performance session mode. The matrix is also verified
against the built package wheel. Reproduce it with:

```bash
PYTHONPATH=. .venv/bin/python scripts/crypto_analysis.py
```

The report is exploratory and does not establish cryptographic security or replace an independent audit.

For upgrade details from 0.1.5, see the dedicated [upgrade guide](UPGRADING_FROM_0_1_5.md).

## Development

Clone the repository and install the development dependencies in a virtual environment:

```bash
git clone https://github.com/hakandamar/fibcrypt.git
cd fibcrypt
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

Run the test and quality checks:

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/python -m build
.venv/bin/twine check dist/*
PYTHONPATH=. .venv/bin/python test/main.py
PYTHONPATH=. .venv/bin/python scripts/nist_sp800_22.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for pull request and development guidelines. Continuous integration runs tests on
the supported Python range.

## Security

Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not include real credentials,
deployment peppers, or customer data in issues, pull requests, or benchmark files.

## License

This project is licensed under the [MIT License](LICENSE).
