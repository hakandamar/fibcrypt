# Benchmark Results

## v1

- Date: 2026-08-22
- Python: 3.14
- Platform: macOS, Apple Silicon
- Configuration: `encrypt`/`decrypt` default `iterations=20`, `prime=65537`
- Measurement: wall-clock time via `time.perf_counter()`; one sample per operation
- Validation: every decrypt result matched the original plaintext

| Operation | Input | Time |
| --- | ---: | ---: |
| `derive_key(iterations=1)` | password + salt | 177.221 ms |
| `derive_key(iterations=5)` | password + salt | 885.103 ms |
| `derive_key(iterations=20)` | password + salt | 3560.494 ms |
| `encrypt` | 16 B | 3464.447 ms |
| `decrypt` | 16 B | 3424.000 ms |
| `encrypt` | 1 KiB | 3519.023 ms |
| `decrypt` | 1 KiB | 3491.223 ms |
| `encrypt` | 1 MiB | 3431.907 ms |
| `decrypt` | 1 MiB | 3517.103 ms |

## Notes

- Runtime is dominated by the Fibonacci-based KDF; payload size has little effect at these sizes.
- `encrypt` and `decrypt` override `derive_key`'s own default iteration count of `250` with `20`.
- The 1 MiB encryption throughput was approximately `0.29 MiB/s`.

## v2

- Date: 2026-08-22
- Change: Fibonacci matrix multiplication now reduces every result modulo `prime`.
- Python: 3.14
- Platform: macOS, Apple Silicon
- Configuration: `encrypt`/`decrypt` default `iterations=20`, `prime=65537`
- Measurement: wall-clock time via `time.perf_counter()`; 7 samples after 1 warmup

| Operation | Input | Mean | Median | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| `derive_key(iterations=1)` | password + salt | 0.016 ms | 0.014 ms | 0.013 ms | 0.024 ms |
| `derive_key(iterations=5)` | password + salt | 0.061 ms | 0.058 ms | 0.058 ms | 0.077 ms |
| `derive_key(iterations=20)` | password + salt | 0.235 ms | 0.237 ms | 0.208 ms | 0.263 ms |
| `encrypt` | 16 B | 0.218 ms | 0.212 ms | 0.207 ms | 0.258 ms |
| `decrypt` | 16 B | 0.207 ms | 0.207 ms | 0.204 ms | 0.210 ms |
| `encrypt` | 1 KiB | 0.212 ms | 0.212 ms | 0.210 ms | 0.214 ms |
| `decrypt` | 1 KiB | 0.224 ms | 0.208 ms | 0.208 ms | 0.286 ms |
| `encrypt` | 1 MiB | 4.111 ms | 4.085 ms | 4.029 ms | 4.214 ms |
| `decrypt` | 1 MiB | 3.603 ms | 3.611 ms | 3.473 ms | 3.779 ms |

### Comparison

- Default KDF time improved from `3560.494 ms` to `0.235 ms`, approximately `15,000x` faster.
- 16 B encryption improved from `3464.447 ms` to `0.218 ms`, approximately `16,000x` faster.
- 1 MiB encryption throughput improved from approximately `0.29 MiB/s` to `243 MiB/s`.

## v3

- Date: 2026-08-22
- Change: Replaced recursive matrix exponentiation with modular fast-doubling Fibonacci.
- Python: 3.14
- Platform: macOS, Apple Silicon
- Configuration: `encrypt`/`decrypt` default `iterations=20`, `prime=65537`
- Measurement: wall-clock time via `time.perf_counter()`; 7 samples after 1 warmup

| Operation | Input | Mean | Median | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| `derive_key(iterations=1)` | password + salt | 0.008 ms | 0.006 ms | 0.006 ms | 0.018 ms |
| `derive_key(iterations=5)` | password + salt | 0.019 ms | 0.019 ms | 0.019 ms | 0.021 ms |
| `derive_key(iterations=20)` | password + salt | 0.069 ms | 0.068 ms | 0.066 ms | 0.073 ms |
| `encrypt` | 16 B | 0.087 ms | 0.084 ms | 0.075 ms | 0.116 ms |
| `decrypt` | 16 B | 0.078 ms | 0.078 ms | 0.075 ms | 0.082 ms |
| `encrypt` | 1 KiB | 0.081 ms | 0.082 ms | 0.077 ms | 0.089 ms |
| `decrypt` | 1 KiB | 0.085 ms | 0.082 ms | 0.077 ms | 0.094 ms |
| `encrypt` | 1 MiB | 3.833 ms | 3.832 ms | 3.716 ms | 4.002 ms |
| `decrypt` | 1 MiB | 3.308 ms | 3.304 ms | 3.247 ms | 3.364 ms |

### Comparison

- Default KDF improved from v2 `0.235 ms` to `0.069 ms`, approximately `3.4x` faster.
- 16 B encryption improved from v2 `0.218 ms` to `0.087 ms`, approximately `2.5x` faster.
- 1 MiB encryption throughput improved from approximately `243 MiB/s` to `261 MiB/s`.

## v4

- Date: 2026-08-22
- Change: Increased the default modulus from `65537` to the 256-bit prime `2**256 - 2**32 - 977`.
- Python: 3.14
- Platform: macOS, Apple Silicon
- Configuration: `encrypt`/`decrypt` default `iterations=20`, 256-bit `prime`
- Measurement: wall-clock time via `time.perf_counter()`; 7 samples after 1 warmup

| Operation | Input | Mean | Median | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| `derive_key(iterations=1)` | password + salt | 0.018 ms | 0.015 ms | 0.015 ms | 0.030 ms |
| `derive_key(iterations=5)` | password + salt | 0.070 ms | 0.070 ms | 0.064 ms | 0.078 ms |
| `derive_key(iterations=20)` | password + salt | 0.281 ms | 0.287 ms | 0.250 ms | 0.313 ms |
| `encrypt` | 16 B | 0.287 ms | 0.284 ms | 0.271 ms | 0.322 ms |
| `decrypt` | 16 B | 0.269 ms | 0.275 ms | 0.245 ms | 0.285 ms |
| `encrypt` | 1 KiB | 0.276 ms | 0.281 ms | 0.252 ms | 0.289 ms |
| `decrypt` | 1 KiB | 0.256 ms | 0.255 ms | 0.251 ms | 0.261 ms |
| `encrypt` | 1 MiB | 4.058 ms | 4.015 ms | 3.962 ms | 4.278 ms |
| `decrypt` | 1 MiB | 3.517 ms | 3.500 ms | 3.426 ms | 3.641 ms |

### Comparison

- Default KDF changed from v3 `0.069 ms` to `0.281 ms`, approximately `4.1x` slower.
- 16 B encryption changed from v3 `0.087 ms` to `0.287 ms`, approximately `3.3x` slower.
- 1 MiB encryption throughput is approximately `246 MiB/s`, versus v3's `261 MiB/s`.
- The larger modulus increases the KDF's output range to 256 bits while keeping sub-millisecond edge latency.

## v6

- Date: 2026-08-22
- Change: Added a random 16-byte salt, HMAC-SHA256 authentication, and versioned `FC2` payload format.
- Python: 3.14
- Platform: macOS, Apple Silicon
- Configuration: default `iterations=128`, 256-bit `prime`
- Measurement: wall-clock time via `time.perf_counter()`; 7 samples after 1 warmup

| Operation | Input | Mean | Median | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| `encrypt` | 16 B | 2.918 ms | 2.940 ms | 2.326 ms | 3.308 ms |
| `decrypt` | 16 B | 2.325 ms | 2.309 ms | 2.251 ms | 2.421 ms |
| `encrypt` | 1 KiB | 2.975 ms | 3.051 ms | 2.524 ms | 3.157 ms |
| `decrypt` | 1 KiB | 2.995 ms | 2.992 ms | 2.937 ms | 3.061 ms |
| `encrypt` | 1 MiB | 6.874 ms | 7.114 ms | 6.241 ms | 7.213 ms |
| `decrypt` | 1 MiB | 6.431 ms | 6.407 ms | 6.352 ms | 6.514 ms |

### Comparison

- Small-payload encryption increased from v5 `1.651 ms` to `2.918 ms` because encryption and authentication keys are derived separately.
- Small-payload decryption increased from v5 `1.624 ms` to `2.325 ms` and authenticates before CBC decryption.
- The new payload adds a version marker, 16-byte random salt, and 32-byte HMAC tag.

## v7

- Date: 2026-08-22
- Change: Removed the `seed % 10**6` reduction; the full SHA-256-derived seed is now used.
- Python: 3.14
- Platform: macOS, Apple Silicon
- Configuration: default `iterations=128`, 256-bit `prime`, FC2 + random salt + HMAC payload
- Measurement: wall-clock time via `time.perf_counter()`; 7 samples after 1 warmup

| Operation | Input | Mean | Median | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| `encrypt` | 16 B | 66.421 ms | 66.383 ms | 65.938 ms | 66.914 ms |
| `decrypt` | 16 B | 66.938 ms | 66.932 ms | 66.879 ms | 67.003 ms |
| `encrypt` | 1 KiB | 66.922 ms | 66.989 ms | 66.273 ms | 67.304 ms |
| `decrypt` | 1 KiB | 66.995 ms | 66.763 ms | 66.147 ms | 69.207 ms |
| `encrypt` | 1 MiB | 70.757 ms | 70.879 ms | 69.903 ms | 71.355 ms |
| `decrypt` | 1 MiB | 67.778 ms | 67.130 ms | 66.891 ms | 70.109 ms |

### Offline Guessing Check

- Wrong-password verification: `15.4 guesses/s` on one CPU core.
- Estimated single-core budget in 24 hours: approximately `1.33 million guesses`.
- The former direct `0..999999` seed enumeration attack no longer applies because the full 256-bit seed is used.
- Multi-core and GPU results require a native implementation benchmark; Python timings are not a GPU security claim.

## v8

- Date: 2026-08-22
- Change: Added a required secret pepper to KDF input; pepper is not stored in the payload.
- Python: 3.14
- Platform: macOS, Apple Silicon
- Configuration: default `iterations=128`, 256-bit `prime`, FC2 + random salt + HMAC payload
- Measurement: wall-clock time via `time.perf_counter()`; 7 samples after 1 warmup

| Operation | Input | Mean | Median | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: |
| `encrypt` | 16 B | 67.792 ms | 67.945 ms | 67.017 ms | 68.321 ms |
| `decrypt` | 16 B | 68.359 ms | 68.366 ms | 68.002 ms | 68.763 ms |
| `encrypt` | 1 KiB | 68.496 ms | 68.522 ms | 67.885 ms | 69.209 ms |
| `decrypt` | 1 KiB | 68.990 ms | 68.960 ms | 68.372 ms | 69.654 ms |
| `encrypt` | 1 MiB | 73.394 ms | 73.252 ms | 72.653 ms | 74.404 ms |
| `decrypt` | 1 MiB | 72.841 ms | 72.815 ms | 72.575 ms | 73.438 ms |

### Offline Guessing Check

- With the pepper known to the attacker, wrong-password verification measured `14.8 guesses/s` on one CPU core.
- Estimated known-pepper budget in 24 hours: approximately `1.28 million guesses` per core.
- With the pepper kept secret, a ciphertext-only attacker cannot verify password guesses through this API.

## v5

- Date: 2026-08-22
- Change: Set the default iteration count to `128` for `derive_key`, `encrypt`, and `decrypt`.
- Python: 3.14
- Platform: macOS, Apple Silicon
- Measurement: wall-clock time via `time.perf_counter()`; 7 samples after 1 warmup
- Input: `edge payload`, `benchmark-password`, `benchmark-salt`

| Operation | Mean | Median | Min | Max |
| --- | ---: | ---: | ---: | ---: |
| `derive_key` | 1.707 ms | 1.694 ms | 1.655 ms | 1.801 ms |
| `encrypt` | 1.651 ms | 1.657 ms | 1.581 ms | 1.724 ms |
| `decrypt` | 1.624 ms | 1.610 ms | 1.550 ms | 1.678 ms |
