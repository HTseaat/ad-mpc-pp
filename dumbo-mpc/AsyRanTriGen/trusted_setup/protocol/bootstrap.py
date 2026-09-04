"""Load the isolated qsdh-py build without changing Continuum's environment."""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path


TRUSTED_SETUP_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD_ROOT = TRUSTED_SETUP_ROOT / "build" / "qsdh-py"

_ACTIVATED = False


def upstream_build_root() -> Path:
    override = os.environ.get("TRUSTED_SETUP_QSDH_BUILD")
    return Path(override).resolve() if override else DEFAULT_BUILD_ROOT


def activate_upstream() -> Path:
    """Make the compiled, disposable upstream build importable.

    The immutable snapshot remains under ``upstream/qsdh-py``. Native outputs
    live only in the ignored ``build/qsdh-py`` working copy.
    """

    global _ACTIVATED
    build_root = upstream_build_root()
    if _ACTIVATED:
        return build_root

    ntl_extensions = tuple((build_root / "adkg" / "ntl").glob("_hbmpc_ntl_helpers*.so"))
    pairing_extension = build_root / "pairing" / "pypairing" / "pypairing.so"
    if not build_root.is_dir() or not ntl_extensions or not pairing_extension.is_file():
        raise RuntimeError(
            "isolated qsdh-py native build is missing; run "
            "trusted_setup/scripts/build_upstream.sh first"
        )

    for path in (build_root / "pairing", build_root):
        value = str(path)
        if value not in sys.path:
            sys.path.insert(0, value)

    # Upstream adkg/__init__.py opens adkg/logging.yaml relative to cwd and
    # parses application CLI arguments unless pytest is already imported.
    # Confine both assumptions to this one import operation.
    old_cwd = Path.cwd()
    old_pytest = sys.modules.get("pytest")
    inserted_marker = old_pytest is None
    if inserted_marker:
        sys.modules["pytest"] = types.ModuleType("pytest")
    try:
        os.chdir(str(build_root))
        __import__("adkg")
    finally:
        os.chdir(str(old_cwd))
        if inserted_marker:
            del sys.modules["pytest"]
        elif old_pytest is not None:
            sys.modules["pytest"] = old_pytest

    _ACTIVATED = True
    return build_root

