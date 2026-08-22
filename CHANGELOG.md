# Changelog

All notable changes to `fibcrypt` are documented here.

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
