# Contributing

Contributions are welcome through GitHub pull requests.

## Before You Start

- Read the [README](README.md) and [security policy](SECURITY.md).
- For security vulnerabilities, use the private reporting process instead of
  opening a public issue or pull request.
- Keep changes focused and explain behavior changes in the pull request.

## Development Setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

The package supports Python 3.8 and newer. Run the focused checks before
opening a pull request:

```bash
.venv/bin/python -m pytest
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/python -m build
.venv/bin/twine check dist/*
```

Keep generated artifacts, virtual environments, IDE metadata, and credentials
out of commits. The repository's `.gitignore` contains the expected local-only
patterns.

## Pull Requests

- Include tests for bug fixes and new behavior.
- Update the README or other documentation when public behavior changes.
- Do not claim that benchmark results establish cryptographic security.
- Do not introduce or publish real secrets, credentials, or private data.
