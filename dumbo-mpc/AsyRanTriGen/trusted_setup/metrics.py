"""Stage-9 structured records for successful standalone setup runs."""

from __future__ import annotations

import json
import os
import pickle
import statistics
import tempfile
from pathlib import Path
from typing import Any, Mapping


METRICS_FORMAT = "continuum-trusted-setup-benchmark-v1"


def build_metrics_record(
    *,
    result: Any,
    verification: Mapping[str, bool],
    negative_tests: Mapping[str, bool],
    end_to_end_seconds: float,
    verification_seconds: float,
    serialization_seconds: float,
    srs: Any = None,
    srs_path: Path | None = None,
    kzg_smoke: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    sent = list(result.sent_bytes_per_party)
    messages = list(result.sent_messages_per_party)
    success = (
        all(verification.values())
        and all(negative_tests.values())
        and (kzg_smoke is None or bool(kzg_smoke.get("ok")))
    )
    return {
        "format": METRICS_FORMAT,
        "run_id": result.params.run_id,
        "params": result.params.as_dict(),
        "success": success,
        "protocol_elapsed_seconds": result.elapsed_seconds,
        "end_to_end_elapsed_seconds": end_to_end_seconds,
        "phase_seconds": {
            "setup_adkg_and_double_sharing": result.setup_elapsed_seconds,
            "powers_of_two_squaring": result.squaring_elapsed_seconds,
            "g2_powers": result.g2_powers_elapsed_seconds,
            "all_powers_g": result.g_all_powers_elapsed_seconds,
            "base_link": result.base_link_elapsed_seconds,
            "all_powers_h": result.h_all_powers_elapsed_seconds,
            "final_verification": verification_seconds,
            "serialization": serialization_seconds,
            "continuum_kzg_smoke": (
                None if kzg_smoke is None else kzg_smoke["elapsed_seconds"]
            ),
        },
        "communication": {
            "encoding": f"python-pickle-protocol-{pickle.DEFAULT_PROTOCOL}",
            "scope": "remote payload bytes; excludes self-send and ZMQ/TCP framing",
            "sent_bytes_per_party": sent,
            "sent_bytes_median": statistics.median(sent),
            "sent_bytes_max": max(sent),
            "sent_messages_per_party": messages,
            "sent_messages_median": statistics.median(messages),
            "sent_messages_max": max(messages),
            "sent_bytes_by_outer_tag_per_party": list(result.sent_bytes_by_tag),
        },
        "verification": dict(verification),
        "negative_tests": dict(negative_tests),
        "artifact": (
            None
            if srs is None
            else {
                "path": None if srs_path is None else str(srs_path.resolve()),
                "digest": srs.digest,
                "size_bytes": srs.encoded_size_bytes,
                "requested_powers": srs.requested_powers,
                "effective_powers": srs.effective_powers,
            }
        ),
        "continuum_kzg_smoke": None if kzg_smoke is None else dict(kzg_smoke),
    }


def write_metrics(record: Mapping[str, Any], path: Path | str) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return destination
