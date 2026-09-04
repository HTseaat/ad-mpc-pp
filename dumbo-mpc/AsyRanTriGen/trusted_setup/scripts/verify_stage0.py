#!/usr/bin/env python3
"""Verify the immutable upstream snapshot and Continuum stage-0 baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


TRUSTED_SETUP_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_ROOT = TRUSTED_SETUP_ROOT / "upstream" / "qsdh-py"
SOURCE_LOCK = TRUSTED_SETUP_ROOT / "upstream" / "SOURCE.lock.json"
BASELINE = (
    TRUSTED_SETUP_ROOT / "baseline" / "continuum-protected-files.sha256"
)
# /opt is three parents above AsyRanTriGen and four above trusted_setup.
WORKSPACE_ROOT = TRUSTED_SETUP_ROOT.parents[3]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_manifest() -> tuple[str, int, int]:
    aggregate = hashlib.sha256()
    file_count = 0
    content_bytes = 0

    for path in sorted(candidate for candidate in SNAPSHOT_ROOT.rglob("*") if candidate.is_file()):
        relative = path.relative_to(SNAPSHOT_ROOT).as_posix()
        size = path.stat().st_size
        mode = "755" if path.stat().st_mode & 0o111 else "644"
        aggregate.update(
            f"{mode} {sha256_file(path)} {relative}\n".encode("utf-8")
        )
        file_count += 1
        content_bytes += size

    return aggregate.hexdigest(), file_count, content_bytes


def verify_source() -> list[str]:
    errors: list[str] = []
    lock = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    expected = lock["snapshot_manifest"]
    actual_digest, actual_count, actual_bytes = snapshot_manifest()

    if actual_digest != expected["sha256"]:
        errors.append(
            f"upstream snapshot digest: expected {expected['sha256']}, "
            f"got {actual_digest}"
        )
    if actual_count != expected["file_count"]:
        errors.append(
            f"upstream snapshot file count: expected {expected['file_count']}, "
            f"got {actual_count}"
        )
    if actual_bytes != expected["content_bytes"]:
        errors.append(
            f"upstream snapshot byte count: expected {expected['content_bytes']}, "
            f"got {actual_bytes}"
        )

    license_path = TRUSTED_SETUP_ROOT / "upstream" / lock["license_file"]
    actual_license = sha256_file(license_path)
    if actual_license != lock["license_sha256"]:
        errors.append(
            f"upstream license digest: expected {lock['license_sha256']}, "
            f"got {actual_license}"
        )
    return errors


def verify_baseline() -> list[str]:
    errors: list[str] = []
    for line_number, raw_line in enumerate(
        BASELINE.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            expected, relative = line.split(maxsplit=1)
        except ValueError:
            errors.append(f"invalid baseline record at line {line_number}")
            continue

        path = WORKSPACE_ROOT / relative
        if not path.is_file():
            errors.append(f"protected file missing: {path}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(
                f"protected file changed: {path} (expected {expected}, got {actual})"
            )
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--source-only", action="store_true", help="verify only the qsdh-py snapshot"
    )
    mode.add_argument(
        "--baseline-only",
        action="store_true",
        help="verify only current Continuum protected files",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors: list[str] = []

    if not args.baseline_only:
        source_errors = verify_source()
        errors.extend(source_errors)
        if not source_errors:
            print("PASS upstream snapshot: 324 files at locked manifest digest")

    if not args.source_only:
        baseline_errors = verify_baseline()
        errors.extend(baseline_errors)
        if not baseline_errors:
            print("PASS Continuum baseline: protected files are unchanged")

    if errors:
        for error in errors:
            print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

