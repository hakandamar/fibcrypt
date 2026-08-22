# Security Policy

## Scope

`fibcrypt` is an experimental cryptographic toolkit. Its Fibonacci-based KDF
and protocol formats have not received an independent cryptographic audit.
Security reports are welcome, especially reports involving authentication
failures, nonce or sequence-number reuse, key derivation, secret handling, or
ciphertext parsing.

Do not use this project for high-assurance or regulated cryptographic
requirements without an independent review. Prefer independently reviewed,
standard cryptographic libraries when the threat model or compliance
requirements call for them.

## Reporting A Vulnerability

Please do not disclose suspected vulnerabilities in a public GitHub issue,
discussion, or pull request.

Use GitHub's private vulnerability reporting for this repository when it is
available. If private reporting is unavailable, email
[hakan.damar@linux.com](mailto:hakan.damar@linux.com) with the subject
`fibcrypt security report`.

Include, when possible:

- The affected version or commit
- A minimal reproduction or proof of concept
- The expected and observed behavior
- The security impact and any known mitigations
- A preferred contact method for follow-up

Please do not include production secrets, personal data, or sensitive customer
information in a report.

## Response Process

Reports will be reviewed privately. The maintainer will work with the reporter
to understand the impact, develop a fix where appropriate, and coordinate
public disclosure after users have a reasonable opportunity to update.

## Supported Versions

Only the latest stable release is currently expected to receive security fixes.
Users should upgrade to the newest release before reporting issues that may
already be fixed.
