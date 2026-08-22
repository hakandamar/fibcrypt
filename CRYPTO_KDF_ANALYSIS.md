# Fibcrypt KDF Analysis

This report documents a reproducible, implementation-level analysis of the current Fibonacci-based KDF and its public
encryption formats.

The analysis intentionally uses synthetic public test inputs. It does not contain production passwords, deployment
peppers, ciphertexts, or customer data.

## Executive Summary

The analysis did not find or demonstrate a practical ciphertext-only attack that recovers the password or pepper from a
Fibcrypt ciphertext. The tested outputs were unique over the sampled default-modulus inputs, related-output identities
behaved exactly as predicted by the XOR construction, and HKDF removed the tested simple arithmetic relation between
related public inputs.

The result depends on the attacker scenario:

| Attacker inputs | Result |
| --- | --- |
| Ciphertext, password, salt, and pepper | Normal decryption is possible; this is not a cryptanalytic break. |
| Ciphertext only, with password and pepper unavailable | No practical key-recovery method was demonstrated in this analysis. |
| Ciphertext, known pepper, and weak/guessable password | Dictionary guessing may be practical; the measured cost was about 59 KDF candidates/second on the test machine. |
| Ciphertext alongside a file that also stores the credentials | The ciphertext is trivially decryptable because the required inputs are present. |

The salt, session ID, direction, and sequence number are not substitutes for the password and secret pepper. The FC7
authentication tag detects tampering, but it does not protect a ciphertext after the required key material has been
recovered.

## Public Format Matrix

The same current `README.md` plaintext was encrypted and decrypted through the public package API for every supported
combination. The test used the default KDF parameters and synthetic credentials. The direct `encrypt()` and `decrypt()`
cases used no optional settings. Context cases used the minimum configuration required by their format.

The matrix was run both from the repository implementation and from the built `fibcrypt-1.2.0` wheel installed into a
clean temporary target. Both runs produced the same format, size, and round-trip results.

Plaintext size: `18,387` bytes.

| Case | Public API | Cipher | Replay | High performance | Wire format | Ciphertext size | Overhead | Round-trip |
| --- | --- | --- | --- | --- | --- | ---: | ---: | --- |
| Default AES | `encrypt()` / `decrypt()` | AES-GCM | No | No | FC3 | 18,434 B | 47 B | Pass |
| Default ChaCha | `encrypt()` / `decrypt()` | ChaCha20-Poly1305 | No | No | FC5 | 18,434 B | 47 B | Pass |
| Replay AES | `CryptoContext` | AES-GCM | Yes | No | FC4 | 18,442 B | 55 B | Pass |
| Replay ChaCha | `CryptoContext` | ChaCha20-Poly1305 | Yes | No | FC6 | 18,442 B | 55 B | Pass |
| Session AES | `CryptoContext` | AES-GCM | No | Yes | FC7 | 18,430 B | 43 B | Pass |
| Session AES + replay | `CryptoContext` | AES-GCM | Yes | Yes | FC7 | 18,430 B | 43 B | Pass |
| Session ChaCha | `CryptoContext` | ChaCha20-Poly1305 | No | Yes | FC8 | 18,430 B | 43 B | Pass |
| Session ChaCha + replay | `CryptoContext` | ChaCha20-Poly1305 | Yes | Yes | FC8 | 18,430 B | 43 B | Pass |

The default package call therefore produces `FC3` with AES-GCM and `FC5` with ChaCha20-Poly1305. Enabling replay
protection changes the stateless formats to `FC4`/`FC6` and adds the authenticated sequence number. High-performance
mode produces `FC7`/`FC8`; the replay flag does not change the wire marker in session mode, but it still controls
receiver replay-window enforcement.

## Scope

The current KDF derives a 256-bit seed with HKDF and then computes:

```text
G_p(s) = XOR { F(s + i) mod p : 0 <= i < 128 }
```

where `p` defaults to:

```text
2**256 - 2**32 - 977
```

The implementation uses HKDF-Extract with the deployment pepper as the HMAC salt, length-prefixed fields for
`fibcrypt-kdf-v2`, `password`, and `salt`, and HKDF-Expand with the info string `fibcrypt-seed` to produce the 32-byte
seed.

The experiments cover:

- The exact related-output identity implied by the XOR window.
- Full-period collision and preimage behaviour for small prime moduli.
- Output uniqueness, bit balance, and output size for the default modulus.
- Hamming-weight behaviour for selected related seeds.
- Related-input behaviour before the Fibonacci aggregation, after HKDF mixing.
- Direct known-pepper KDF cost on the development machine.

## Reproduction

Run from the repository root:

```bash
PYTHONPATH=. .venv/bin/python scripts/crypto_analysis.py
```

The default run uses 4096 deterministic pseudo-random 256-bit seeds and seven timed KDF samples. The script reports
whether `gmpy2` was enabled. To choose a different sample count:

```bash
PYTHONPATH=. .venv/bin/python scripts/crypto_analysis.py \
  --samples 4096 --benchmark-samples 7
```

The deterministic sample generator uses the fixed analysis seed `0xF1BC0DE`. The password, salt prefix, and pepper in
the script are synthetic analysis constants and are not project credentials.

## Results

The measurements below were produced on the development machine with Python 3.14 and `gmpy2` enabled. Timings are
hardware- and load-dependent.

### Related-output identity

For `1 <= k <= 128`, direct expansion gives the identity:

```text
G_p(s) XOR G_p(s + k)
  = XOR { F(s + i) mod p : 0 <= i < k }
    XOR { F(s + 128 + i) mod p : 0 <= i < k }
```

The script verified this identity for offsets `1`, `2`, `3`, `7`, `31`, and `128`, using 32 default-modulus seeds for
each offset. Related seeds therefore produce related outputs under the XOR window, exactly as predicted by the
construction.

### Small-prime collision experiments

For each small prime, the script enumerated one complete period of the pair `(F(n), F(n+1)) mod p`. The domain is
therefore one Fibonacci period, not a 256-bit seed domain.

| Prime | Period | Unique outputs | Collisions | Max preimages for one output | Preimages of `G(0)` |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 8 | 1 | 7 | 8 | 8 |
| 5 | 20 | 8 | 12 | 4 | 2 |
| 7 | 16 | 1 | 15 | 16 | 16 |
| 11 | 10 | 8 | 2 | 3 | 1 |
| 13 | 28 | 14 | 14 | 4 | 2 |
| 17 | 36 | 17 | 19 | 6 | 2 |
| 31 | 30 | 14 | 16 | 5 | 5 |
| 101 | 50 | 42 | 8 | 2 | 1 |
| 257 | 516 | 327 | 189 | 7 | 2 |
| 1009 | 126 | 113 | 13 | 3 | 3 |

These results confirm that the construction is not injective over small periodic domains. The especially degenerate
results for primes `3` and `7` are expected from the relationship between their Fibonacci periods and the 128-term XOR
window. They are useful sanity checks, but they cannot be extrapolated as collision probabilities for the default
256-bit modulus.

The small-prime preimage counts are exhaustive only within the listed period. No exhaustive preimage search is possible
for the default 256-bit seed space.

### Default-modulus output statistics

Using 4096 deterministic 256-bit seeds and the default modulus:

| Measurement | Result |
| --- | ---: |
| Unique outputs | 4096 / 4096 |
| Minimum output bit length | 244 |
| Maximum output bit length | 256 |
| Mean number of one bits per output bit position | 2048.6914 / 4096 |
| Minimum one count for a bit position | 1977 |
| Maximum one count for a bit position | 2138 |
| Largest absolute per-bit bias | 0.0219727 |
| Bit with largest observed bias | 42 |
| Minimum uncorrected per-bit balance p-value | 0.0049158 |

The 4096 sampled outputs were all distinct. The largest per-bit deviation was about 2.2%. The smallest p-value is not
sufficient evidence of a structural defect: 256 bit positions were tested independently, so this is a multiple-
comparisons setting. A Bonferroni-adjusted 0.01 threshold would be about `0.0000391`; the observed value is above that
threshold. The most biased bit also changed between the 512- and 4096-sample exploratory runs, which is consistent with
sample noise rather than a confirmed persistent bias.

### Differential Hamming weights

For 128 sampled seeds, the script measured the Hamming weight of `G_p(s) XOR G_p(s + k)`:

| Offset `k` | Mean | Minimum | Maximum |
| ---: | ---: | ---: | ---: |
| 1 | 128.1953 | 108 | 149 |
| 2 | 127.0703 | 109 | 144 |
| 3 | 126.9844 | 98 | 154 |
| 7 | 127.3125 | 107 | 145 |
| 31 | 128.4453 | 102 | 151 |

The means are close to the 128-bit midpoint expected for a 256-bit XOR difference under a basic random-looking
heuristic.

### HKDF related-input separation

The script held the synthetic password fixed and derived 4096 adjacent seeds from salts `analysis-salt-0` through
`analysis-salt-4095`:

| Measurement | Result |
| --- | ---: |
| Adjacent pairs | 4096 |
| Pairs satisfying `seed[i+1] == seed[i] + 1` | 0 |
| Mean adjacent seed Hamming distance | 128.0205 bits |
| Minimum adjacent seed Hamming distance | 101 bits |
| Maximum adjacent seed Hamming distance | 157 bits |

The result is consistent with HKDF destroying simple arithmetic relatedness between the public salt inputs and the
Fibonacci seeds.

### Known-pepper KDF cost

With the synthetic password, salt, and pepper known to the benchmark, seven KDF calls after two warmups took
approximately `17.0 ms` each, or about `59 candidates/second`, with `gmpy2` enabled on the development machine.

The KDF is latency-oriented rather than memory-hard; `iterations=128` is a fixed work factor for this benchmark.
Hardware, Python version, `gmpy2`, parallelism, and attacker implementation affect the measured rate.

## Conclusions

### Observed

- The implementation matches the exact related-output XOR identity for the tested offsets.
- Small periodic domains contain collisions and non-uniform preimage counts.
- The tested default-modulus outputs were unique for 4096 sampled seeds.
- Basic bit-balance and selected differential Hamming measurements showed no confirmed large anomaly in these samples.
- HKDF input mixing removed the tested adjacent-seed relation.
- A known-pepper guess costs roughly one KDF call per 17.0 ms on the test machine with acceleration enabled.

### Scope Boundary

The measurements are sample-based and do not cover exhaustive preimage search over the default 256-bit domain, optimized
parallel guessing, side-channel behaviour, or advanced algebraic/differential analysis. The format matrix validates the
package integration and authenticated round-trip behaviour; the AEAD primitives are not analyzed internally.

## Follow-up Work

Useful next investigations include:

- Repeat the output tests across independent seeds and larger samples.
- Compare the default prime with other large primes and parameter choices.
- Factor or independently verify relevant Fibonacci periods for additional small-prime diagnostics.
- Investigate algebraic and differential properties with a separate implementation.
- Benchmark pure Python and accelerated paths separately on target edge hardware.
