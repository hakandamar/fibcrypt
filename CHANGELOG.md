# Changelog

All notable changes to `fibcrypt` are documented here.

## v1.2.1 — 2026-09-12

### Performance

- Key derivation is now approximately 75–86x faster via a chained Fibonacci
  identity: consecutive `F(seed..seed+k)` values use one fast-doubling pass
  plus modular additions instead of one full pass per value. Derived keys are
  bit-for-bit identical; no wire format or ciphertext changes were made, and
  FC2–FC8 remain compatible.

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

The FC3–FC6 figures are reference measurements from the x86_64 benchmark; see
`bench_results.md` for the Apple Silicon v1.2.1 run.

### Security notes

- Faster legitimate operations also make offline guessing faster for an
  attacker who has already compromised both the salt and pepper. New
  deployments that upgrade both endpoints together are encouraged to raise
  `iterations` to 2048. The default remains `iterations=128` for compatibility,
  and KDF parameters must match at both endpoints because they are not embedded
  in payloads.
- `gmpy2` is optional; the v1.2.1 chain does not require it for correctness.

### Tests

- Added chain-equivalence tests and deterministic v1.2.0 cross-version
  fixtures proving that FC3–FC8 ciphertexts decrypt on v1.2.1.

## [1.2.0] - 2026-08-22

### Added

- Opt-in high-performance session mode with `FC7` AES-GCM and `FC8`
  ChaCha20-Poly1305 payloads.
- Session-key derivation that runs once per configured session endpoint.
- Authenticated sequence-derived nonces for high-performance session messages.
- Tests covering session setup, replay protection, direction binding, AAD, and
  malformed or mismatched session payloads.
- Public security policy, contribution guide, package metadata, and GitHub CI.

### Changed

- Updated the package version to `1.2.0`.
- Documented the experimental status and unaudited cryptographic construction.
