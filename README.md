# fibcrypt

`fibcrypt` is an open-source, edge-oriented encryption toolkit that combines a Fibonacci-based key derivation design with AES-256-GCM authenticated encryption.

It is designed for applications that need many low-latency encryption/decryption operations and want to evaluate an alternative, transparent cryptographic construction. It is **not** presented as a replacement for Argon2, scrypt, or other independently reviewed password KDFs.

## What It Provides

- Fibonacci-based key derivation using modular fast-doubling arithmetic
- A 256-bit default modulus and full SHA-256-derived seed
- AES-256-GCM authenticated encryption in the current `FC3` format
- Legacy authenticated `FC2` AES-CBC/HMAC payload decryption for migration
- A fresh random salt and nonce for every encryption
- A required deployment secret (`pepper`) kept outside the ciphertext
- Versioned `FC3` ciphertext payloads by default
- Optional `FC4` sequence-number binding and in-process replay protection

## Security Model

Each encryption requires four inputs:

- `plaintext`: the data to encrypt
- `password`: the user/application password
- `salt`: caller-provided context; it may be public, but must be supplied again for decryption
- `pepper`: a secret deployment value that must not be stored in the ciphertext or source code

The pepper must contain at least 32 UTF-8 bytes. This is a minimum deployment-secret
requirement, not a substitute for choosing a strong password.

The ciphertext contains the version marker, random salt, nonce, encrypted data, and authentication tag:

```text
FC3 + random_salt + nonce + ciphertext + GCM tag
```

Decryption authenticates the GCM tag before returning plaintext. Modified or truncated ciphertexts, wrong passwords, wrong salts, and wrong peppers are rejected.

### Optional Replay Protection

Replay protection is disabled by default, so the existing `encrypt()` and
`decrypt()` API continues to use the stateless `FC3` format. Applications that
process ordered control or telemetry messages can opt in through
`CryptoContext`:

```python
from fibcrypt.crypto_utils import CryptoContext

sender = CryptoContext(password, salt, pepper, replay_protection=True)
receiver = CryptoContext(password, salt, pepper, replay_protection=True)

ciphertext = sender.encrypt(message, sequence_number=42, aad=b"device-7/telemetry")
plaintext = receiver.decrypt(ciphertext, aad=b"device-7/telemetry")
```

When enabled, `sequence_number` is required and new payloads use the `FC4`
format. The sequence number is authenticated by AES-GCM and the receiver uses
a thread-safe sliding replay window. Duplicate or sufficiently old sequence
numbers are rejected. `aad` can bind a message to a device, channel, or
message type, but must be supplied identically during decryption.

The in-process replay window does not coordinate multiple application
instances. Distributed deployments must provide shared atomic replay state at
the application or infrastructure layer.

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

## Usage

Set the pepper through a secret manager or environment variable. Do not commit it to source control.

```bash
export FIBCRYPT_PEPPER="your-long-random-deployment-secret"
```

```python
import os

from fibcrypt.crypto_utils import decrypt, encrypt

message = "This is a secret message"
password = "my-strong-password"
salt = "application-context"
pepper = os.environ["FIBCRYPT_PEPPER"]

ciphertext = encrypt(message, password, salt, pepper)
print("Encrypted:", ciphertext.hex())

plaintext = decrypt(ciphertext, password, salt, pepper)
print("Decrypted:", plaintext)
```

`encrypt` returns `bytes`. Store or transmit those bytes directly, or encode them as hexadecimal/base64. Keep the `salt` and `pepper` available to the decrypting service; only the pepper must remain secret.

Wrong credentials and tampered ciphertext raise `ValueError` during authentication.

## Parameters

The default public API uses:

- `iterations=128`
- `prime=2**256 - 2**32 - 977`

Both can be overridden explicitly for experiments and benchmarks. Changing these values changes the derived keys, so the parameters must remain consistent between encryption and decryption.

## Performance

On the development benchmark machine (Python 3.14, Apple Silicon, 7 samples after one warmup), v1.1 measured approximately:

| Payload | v1.0 Encrypt | v1.1 Encrypt | v1.0 Decrypt | v1.1 Decrypt |
| ---: | ---: | ---: | ---: | ---: |
| 16 B | 67.8 ms | 33.36 ms | 68.4 ms | 33.50 ms |
| 1 KiB | 68.5 ms | 34.10 ms | 69.0 ms | 33.87 ms |
| 1 MiB | 73.4 ms | 39.99 ms | 72.8 ms | 40.01 ms |

These are reference measurements, not performance guarantees. Benchmark the target edge hardware before deployment.

### PyPI 0.1.5 vs v1.1

The following comparison was run on the same machine against the published PyPI `0.1.5` wheel and the v1.1 implementation. The legacy release used its original `iterations=20` default and unauthenticated AES-CBC format; v1.1 uses `iterations=128`, full-seed derivation, a secret pepper, random salt, and authenticated encryption. This is therefore a release comparison, not an equal-security-configuration comparison.

| Payload | 0.1.5 Encrypt | v1.1 Encrypt | Speedup | 0.1.5 Decrypt | v1.1 Decrypt | Speedup |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16 B | 3443 ms | 33.36 ms | 103.2x | 3446 ms | 33.50 ms | 102.9x |
| 1 KiB | 3471 ms | 34.10 ms | 101.8x | 3497 ms | 33.87 ms | 103.2x |
| 1 MiB | 3524 ms | 39.99 ms | 88.1x | 3507 ms | 40.01 ms | 87.6x |

The legacy values used three timed samples after one warmup; v1.1 values used seven timed samples after one warmup. Values are rounded and will vary by hardware.

## Security Improvements

Compared with the original PyPI `fibcrypt 0.1.5` release, `fibcrypt 1.1` includes:

- Modular fast-doubling Fibonacci arithmetic instead of unbounded intermediate matrix growth
- A 256-bit default modulus instead of `65537`
- The full SHA-256-derived seed instead of a directly enumerable `seed % 10**6` space
- A required deployment pepper kept outside the ciphertext and source code
- A fresh random salt for every encryption
- Separate key derivation domains for legacy encryption and authentication
- AES-GCM authenticated encryption instead of a CBC/HMAC composition for new payloads
- Versioned `FC3` payloads with explicit format boundaries
- Optional `FC4` sequence-number binding and in-process replay protection
- Approximately 88-103x lower measured latency than the published `0.1.5` artifact on the benchmark machine

## Statistical Testing

An exploratory run of selected NIST SP 800-22 tests was performed against one
1,000,000-bit stream generated from v1.1 KDF outputs using the default
`iterations=128` and 256-bit prime:

| Test | p-value |
| --- | ---: |
| Frequency (Monobit) | 0.586441 |
| Frequency (Block) | 0.412220 |
| Runs | 0.969452 |
| Longest Run of Ones | 0.063463 |
| Serial | 0.861900 |
| Approximate Entropy | 0.141916 |
| Cumulative Sums | 0.344659 |

All observed p-values exceeded the exploratory threshold of `0.01`. These
results indicate no obvious statistical anomaly in this sample. They do not
prove cryptographic randomness, establish KDF security, or replace the full
NIST Statistical Test Suite, multiple independent sequences, or an
independent cryptographic audit. The reproducible, dependency-free harness is
available at `scripts/nist_sp800_22.py`.

## Upgrading From 0.1.5

Version 1.1 changes both the API and ciphertext format. Existing systems must not be upgraded blindly:

1. Provision one high-entropy pepper through a secret manager or environment variable and make it available to every service that encrypts or decrypts the shared data.
2. Update calls from `encrypt(plaintext, password, salt)` and `decrypt(ciphertext, password, salt)` to include the same pepper value.
3. Keep the original `0.1.5` runtime available while migrating existing data.
4. Decrypt each `0.1.5` ciphertext with the original package and credentials, then re-encrypt it with v1.1 and the managed pepper.
5. Verify the migrated plaintext or application record before replacing the old ciphertext.
6. Test the migration on a backup or staging copy before rolling it out to production.

The v0.1.5 format was `iv + ciphertext` and used different key derivation defaults. It has no authentication tag and is not readable by the `FC2`/`FC3`/`FC4` decoder. Existing authenticated `FC2` payloads remain decryptable, while new default calls produce `FC3` AES-GCM payloads. Replay-protected calls produce `FC4` payloads. Losing the pepper makes ciphertexts unrecoverable.

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
