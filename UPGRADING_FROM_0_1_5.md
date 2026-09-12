# Upgrading From fibcrypt 0.1.5

This guide covers migration from the original `fibcrypt 0.1.5` package to the
current authenticated formats in fibcrypt v1.2.1.

## Migration steps

Version 1.2.1 changes neither the current `FC3`/`FC4` wire format nor the
v1.1.1 KDF for default payloads. It also restores decryption of pre-HKDF v1.1.0
`FC3`/`FC4` payloads and includes the v1.2.0 opt-in `FC7`/`FC8` session mode.
The v1.2.1 KDF optimization is bit-for-bit compatible, so existing current
format ciphertexts do not need to be re-encrypted.

1. Provision one high-entropy pepper through a secret manager or environment
   variable and make it available to every service that encrypts or decrypts
   the shared data.
2. Update calls from `encrypt(plaintext, password, salt)` and
   `decrypt(ciphertext, password, salt)` to include the same pepper value.
3. Keep the original `0.1.5` runtime available while migrating existing data.
4. Decrypt each `0.1.5` ciphertext with the original package and credentials,
   then re-encrypt it with v1.2.1 and the managed pepper.
5. Verify the migrated plaintext or application record before replacing the
   old ciphertext.
6. Test the migration on a backup or staging copy before rolling it out to
   production.

## Format compatibility

The v0.1.5 format was `iv + ciphertext` and used different key derivation
defaults. It has no authentication tag and is not readable by the
`FC2`/`FC3`/`FC4`/`FC5`/`FC6`/`FC7`/`FC8` decoder.

Existing authenticated `FC2` payloads remain decryptable. New default calls
produce `FC3` AES-GCM payloads; replay-protected calls produce `FC4` payloads.
ChaCha20 calls produce `FC5`/`FC6`. High-performance session calls produce
`FC7`/`FC8`. A replay-protected `CryptoContext` requires `FC4` or `FC6` input
and rejects stateless payloads.

Losing the pepper makes ciphertexts unrecoverable. Keep it outside ciphertexts,
source code, fixtures, logs, and benchmark output.
