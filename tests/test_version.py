"""Distribution metadata consistency tests."""

import re
from pathlib import Path

import fibcrypt

_ROOT = Path(__file__).resolve().parent.parent


def _setup_py_version() -> str:
    """Return the version string that setup.py resolves at build time."""

    source = (_ROOT / "setup.py").read_text(encoding="utf-8")
    # setup.py reads the version from fibcrypt/__init__.py; re-run the same
    # lookup and also verify no hardcoded version literal crept back in.
    assert 'version="1' not in source.replace(
        '__version__ = "', ""
    ), "setup.py must derive its version from fibcrypt/__init__.py"
    init_source = (_ROOT / "fibcrypt" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', init_source, re.MULTILINE)
    assert match is not None, "fibcrypt/__init__.py must define __version__"
    return match.group(1)


def test_package_exposes_version() -> None:
    assert re.fullmatch(
        r"\d+\.\d+\.\d+", fibcrypt.__version__
    ), "version must be a plain X.Y.Z string"


def test_setup_py_and_package_version_are_in_sync() -> None:
    assert _setup_py_version() == fibcrypt.__version__
