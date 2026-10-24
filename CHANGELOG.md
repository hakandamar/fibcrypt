# Changelog

All notable changes to `fibcrypt` are documented here.

## v1.2.2 — 2026-10-24

### Security hardening

This release closes the actionable findings of an internal security review of
v1.2.1. No wire formats changed; FC2-FC8 remain fully compatible.

- Session-mode senders are now protected against AEAD nonce reuse: within one
  `CryptoContext` in high-performance (FC7/FC8) mode, `encrypt()` rejects any
  `sequence_number` that is not greater than the last sequence number sent
  from that context. Reusing a sequence number under a single session key
  repeats the GCM/ChaCha20-Poly1305 nonce and leaks the keystream XOR of the
  two plaintexts, so the check is enforced by default. `decrypt()` never
  changes this sender state. The escape hatch `allow_sequence_reuse=True`
  disables the check (with a one-time warning) for controlled recovery or
  testing only.
- Decrypting `FC4`/`FC6` replay-protected payloads without an active replay
  guard (the stateless `decrypt()` or a context with
  `replay_protection=False`) now logs a warning on every such message instead
  of silently accepting possible replays. The new `strict_replay=True` option
  (on `CryptoContext` and on the stateless `decrypt()`) rejects those
  unguarded decryptions with `ValueError`.
- Creating a high-performance context with the default `direction` now logs a
  construction-time warning: both endpoints keeping the default on the same
  session ID derive the same session key and share one nonce space. Pass
  distinct directions (for example `uplink`/`downlink`) for bidirectional
  channels.
- The derived-key cache no longer stores the raw pepper string. Each cache key
  now embeds a one-way HMAC-SHA256 commitment of the pepper, so inspecting the
  cache (dumps, reprs, debug tooling) does not expose the deployment secret.
  Key derivation and every derived key are bit-for-bit unchanged. Long-lived
  processes can call `ctx.clear_cache()` when idle to release cached key
  material early.
- Repeated decryption of the same corrupted or forged `FC3`/`FC4` payload no
  longer re-runs the pre-HKDF legacy key derivation. Failed legacy fallbacks
  are remembered in a bounded, thread-safe FIFO set (1024 entries), cutting
  the worst-case double-KDF cost per repeated bad payload. The observable
  error is unchanged and genuine legacy ciphertexts are unaffected.
- New encryption setups using `iterations` below the recommended work factor
  now log a one-time warning, and the new `RECOMMENDED_ITERATIONS` constant
  (2048) is exported. The historical `128` default stays for wire
  compatibility; decryption paths never warn because a ciphertext must always
  be opened with the iteration count it was created with.
- Runtime dependencies are upper-bounded: `pycryptodomex>=3.22,<4` and the
  optional `gmpy2>=2.1,<3` extra, limiting silent supply-chain behavior
  changes across major versions.

### Compatibility notes

- Existing code that used strictly increasing session sequence numbers is
  unaffected. Code that intentionally replayed sequence numbers (previously a
  silent cryptographic break) now receives a `ValueError` unless
  `allow_sequence_reuse=True` is set.
- The new warnings do not change return values; use `strict_replay=True` to
  opt into hard rejection of unguarded `FC4`/`FC6` decryptions.

### Quality

- 33 security-hardening regression tests in total (13 added in the second batch
  with the parametrized cases counted) plus version-metadata sync guards;
  `344 passed` overall at `97%` coverage. The hardening suite covers sequence
  monotonicity, replay-guard warnings and
  `strict_replay`, pepper-commitment cache keys, the failed-legacy-fallback
  cache, and the one-time low-iterations warning.
- The package now exposes `fibcrypt.__version__`, and `setup.py` derives the
  distribution version from it, eliminating the second version literal.

### Performance

- A repeat benchmark A/B on Apple Silicon (see `bench_results.md`, v1.2.2 run) shows
  no measurable cost from the hardening: every operation stays within ±2% of the
  pre-hardening baseline, including the FC7/FC8 session hot path with the new
  sender sequence lock.
- FC4/FC6 decrypt medians re-measure about 10-15 µs higher than the 2026-09-12
  v1.2.1 table (0.047/0.031 ms versus 0.034/0.022 ms). The A/B run attributes this
  to the test environment (patch-level Python 3.14.9 / macOS 26.7.1), not to
  v1.2.2 code changes.

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
