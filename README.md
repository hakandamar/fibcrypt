# fibcrypt

`fibcrypt` is an open-source, edge-oriented encryption toolkit that combines a Fibonacci-based key derivation design with AES-256-GCM authenticated encryption.

It is designed for applications that need many low-latency encryption/decryption operations and want to evaluate an alternative, transparent cryptographic construction. It is **not** presented as a replacement for Argon2, scrypt, or other independently reviewed password KDFs.

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
- **Thread-safe bounded key caching** in `CryptoContext` for repeated decryptions
- **gmpy2 acceleration** (optional, with pure Python fallback) for ~4x KDF speedup

## Security Model

Each encryption requires four inputs:

- `plaintext`: the data to encrypt
- `password`: the user/application password
- `salt`: caller-provided context; it may be public, but must be supplied again for decryption
- `pepper`: a secret deployment value that must not be stored in the ciphertext or source code

The pepper must contain at least 32 UTF-8 bytes. This is a minimum deployment-secret requirement, not a substitute for choosing a strong password.

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

Decryption authenticates the tag before returning plaintext. Modified or truncated ciphertexts, wrong passwords, wrong salts, and wrong peppers are rejected.

### Optional Replay Protection

Replay protection is disabled by default, so the existing `encrypt()` and `decrypt()` API continues to use the stateless `FC3` format. Applications that process ordered control or telemetry messages can opt in through `CryptoContext`:

```python
from fibcrypt.crypto_utils import CryptoContext

sender = CryptoContext(password, salt, pepper, replay_protection=True)
receiver = CryptoContext(password, salt, pepper, replay_protection=True)

ciphertext = sender.encrypt(message, sequence_number=42, aad=b"device-7/telemetry")
plaintext = receiver.decrypt(ciphertext, aad=b"device-7/telemetry")
```

When enabled, `sequence_number` is required and new payloads use the `FC4` (AES-GCM) or `FC6` (ChaCha20) format. The sequence number is authenticated by the AEAD cipher and the receiver uses a thread-safe sliding replay window. Duplicate or sufficiently old sequence numbers are rejected. `aad` can bind a message to a device, channel, or message type, but must be supplied identically during decryption.

The in-process replay window does not coordinate multiple application instances. Distributed deployments must provide shared atomic replay state at the application or infrastructure layer.

For a ciphertext-only attacker who has no password, caller salt, or pepper, the payload and public source code are not sufficient to derive the keys. This assumes the deployment pepper is a high-entropy secret and is not embedded in application source, test configuration, logs, or the payload.

Important limitations:

- The Fibonacci KDF is custom and has not received an independent cryptographic audit.
- `iterations=128` is selected for latency, not as a claim of equivalence to a memory-hard password KDF.
- Weak or reused passwords remain vulnerable to dictionary attacks if the attacker also knows or can guess the salt and obtains the pepper.
- The pepper must be managed as a deployment secret and contain at least 32 bytes. If an attacker compromises the application host and reads its secrets, this model no longer applies.
- Do not use this package for high-assurance or regulated cryptographic requirements without an independent review.

## Installation

```bash
pip install fibcrypt
```

**Optional: gmpy2 acceleration** (recommended for ~4x KDF speedup):

```bash
pip install fibcrypt[gmpy2]
# or
pip install gmpy2
```

## Usage

Set the pepper through a secret manager or environment variable. Do not commit it to source control.

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

`encrypt` returns `bytes`. Store or transmit those bytes directly, or encode them as hexadecimal/base64. Keep the `salt` and `pepper` available to the decrypting service; only the pepper must remain secret.

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

Both `iterations` and `prime` can be overridden explicitly for experiments and benchmarks. `iterations` must be positive and `prime` must be greater than one. Changing these values changes the derived keys, so the parameters must remain consistent between encryption and decryption.

## Performance

On the development benchmark machine (Python 3.14, Apple Silicon), the release comparison is:

| Payload | Operation | v1.0.0 | v1.1.2 (pure Python) | v1.1.2 (with gmpy2) |
| --- | --- | ---: | ---: | ---: |
| 16 B | Encrypt | 67.8 ms | 33.097 ms | 16.618 ms |
| 16 B | Decrypt | 68.4 ms | 33.529 ms | 16.693 ms |
| 1 KiB | Encrypt | 68.5 ms | 33.136 ms | 16.518 ms |
| 1 KiB | Decrypt | 69.0 ms | 32.490 ms | 16.562 ms |
| 1 MiB | Encrypt | 73.4 ms | 39.335 ms | 22.765 ms |
| 1 MiB | Decrypt | 72.8 ms | 39.811 ms | 22.975 ms |

All measurements use the default `iterations=128` and 256-bit prime, with seven samples after one warmup. The v1.0.0 values are rounded values recorded in the v1.0.0 distribution metadata; v1.1.2 values were measured on the same Python 3.14/Apple Silicon environment. The v1.1.2 pure-Python column disables gmpy2, while the final column has gmpy2 enabled.

The comparison is performance-oriented, not a wire-format comparison: v1.0.0 uses authenticated `FC2` AES-CBC/HMAC, while v1.1.2 uses authenticated `FC3` AES-GCM. Relative to v1.0.0, v1.1.2 is approximately 1.8-2.1x faster without gmpy2 and 3.2-4.2x faster with gmpy2.

These are reference measurements, not performance guarantees. Benchmark the target edge hardware before deployment.

### PyPI 0.1.5 vs v1.1.2

The following comparison was run on the same machine against the published PyPI `0.1.5` wheel and the v1.1.2 implementation. The legacy release used its original `iterations=20` default and unauthenticated AES-CBC format; v1.1.2 uses `iterations=128`, full-seed derivation, a secret pepper, random salt, and authenticated encryption. This is therefore a release comparison, not an equal-security-configuration comparison.

| Payload | 0.1.5 Encrypt | v1.1.2 Encrypt | Speedup | 0.1.5 Decrypt | v1.1.2 Decrypt | Speedup |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16 B | 3443 ms | 16.6 ms | 207x | 3446 ms | 16.6 ms | 207x |
| 1 KiB | 3471 ms | 16.8 ms | 206x | 3497 ms | 16.9 ms | 207x |
| 1 MiB | 3524 ms | 20.2 ms | 174x | 3507 ms | 19.8 ms | 177x |

The legacy values used three timed samples after one warmup; v1.1.2 values used seven timed samples after one warmup. Values are rounded and will vary by hardware.

## Security Improvements

Compared with the original PyPI `fibcrypt 0.1.5` release, `fibcrypt 1.1.2` includes:

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
- **Thread-safe bounded key caching** in `CryptoContext` for repeated decryptions
- **gmpy2-accelerated Fibonacci arithmetic** with pure Python fallback
- Approximately 174-207x lower measured latency than the published `0.1.5` artifact on the benchmark machine

## Statistical Testing

An exploratory run of selected NIST SP 800-22 tests was performed against one 1,000,000-bit stream generated from the current KDF using the default `iterations=128` and 256-bit prime:

| Test | p-value |
| --- | ---: |
| Frequency (Monobit) | 0.586441 |
| Frequency (Block) | 0.412220 |
| Runs | 0.969452 |
| Longest Run of Ones | 0.063463 |
| Serial | 0.861900 |
| Approximate Entropy | 0.141916 |
| Cumulative Sums | 0.344659 |

All observed p-values exceeded the exploratory threshold of `0.01`. These results indicate no obvious statistical anomaly in this sample. They do not prove cryptographic randomness, establish KDF security, or replace the full NIST Statistical Test Suite, multiple independent sequences, or an independent cryptographic audit. The reproducible, dependency-free harness is available at `scripts/nist_sp800_22.py`.

## Upgrading From 0.1.5

Version 1.1.2 changes neither the current `FC3`/`FC4` wire format nor the v1.1.1 KDF for newly generated payloads. It also restores decryption of pre-HKDF v1.1.0 `FC3`/`FC4` payloads:

1. Provision one high-entropy pepper through a secret manager or environment variable and make it available to every service that encrypts or decrypts the shared data.
2. Update calls from `encrypt(plaintext, password, salt)` and `decrypt(ciphertext, password, salt)` to include the same pepper value.
3. Keep the original `0.1.5` runtime available while migrating existing data.
4. Decrypt each `0.1.5` ciphertext with the original package and credentials, then re-encrypt it with v1.1.2 and the managed pepper.
5. Verify the migrated plaintext or application record before replacing the old ciphertext.
6. Test the migration on a backup or staging copy before rolling it out to production.

The v0.1.5 format was `iv + ciphertext` and used different key derivation defaults. It has no authentication tag and is not readable by the `FC2`/`FC3`/`FC4`/`FC5`/`FC6` decoder. Existing authenticated `FC2` payloads remain decryptable, while new default calls produce `FC3` AES-GCM payloads. Replay-protected calls produce `FC4` payloads. ChaCha20 calls produce `FC5`/`FC6`. A replay-protected `CryptoContext` requires `FC4` or `FC6` input and rejects stateless payloads. Losing the pepper makes ciphertexts unrecoverable.

## Development

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
ruff check .
mypy
PYTHONPATH=. python3 test/main.py
PYTHONPATH=. python3 scripts/nist_sp800_22.py
```

## License

This project is licensed under the MIT License.
