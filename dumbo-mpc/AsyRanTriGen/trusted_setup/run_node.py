"""Run one trusted-setup party over authenticated network channels."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from dataclasses import asdict
from pathlib import Path

from .config import NodeConfig
from .protocol.network import (
    CurveNodeCommunicator,
    load_node_transport,
)


RESULT_MARKER = "TRUSTED_SETUP_NODE_RESULT="
METRICS_FORMAT = "continuum-trusted-setup-distributed-node-v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--timeout", default=300.0, type=float)
    parser.add_argument("--readiness-timeout", default=60.0, type=float)
    parser.add_argument("--output-srs", required=True, type=Path)
    parser.add_argument("--metrics-output", required=True, type=Path)
    parser.add_argument("--kzg-smoke", action="store_true")
    return parser.parse_args()


def _load_node_config(path: Path) -> NodeConfig:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load node configuration {path}: {exc}") from exc
    return NodeConfig.from_dict(value)


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


async def async_main(args: argparse.Namespace) -> int:
    node_config = _load_node_config(args.config)
    params = node_config.params
    party_id = node_config.node_id
    transport_config = load_node_transport(
        args.config,
        party_id=party_id,
        n=params.n,
        run_id=params.run_id,
    )

    # Native qsdh imports are delayed until pure config validation succeeds.
    from .protocol.distributed_tau import run_distributed_party_setup
    from .protocol.verification import (
        tamper_is_rejected,
        tampered_dleq_proof_is_rejected,
        tampered_h_chain_is_rejected,
        tampered_h_commitment_is_rejected,
        verify_distributed_party_result,
    )
    from .serialization import build_srs, write_srs

    end_to_end_started = time.perf_counter()
    async with CurveNodeCommunicator(
        node_config.peers,
        party_id,
        transport_config,
        readiness_timeout=args.readiness_timeout,
    ) as communicator:
        result = await run_distributed_party_setup(
            params,
            party_id=party_id,
            send=communicator.send,
            recv=communicator.recv,
            timeout_seconds=args.timeout,
        )
        transport = communicator.snapshot()

    verification_started = time.perf_counter()
    report = verify_distributed_party_result(result)
    negative_tests = {
        "g_chain_tamper_rejected": tamper_is_rejected(result),
        "h_chain_tamper_rejected": tampered_h_chain_is_rejected(result),
        "h_commitment_tamper_rejected": tampered_h_commitment_is_rejected(result),
        "dleq_proof_tamper_rejected": tampered_dleq_proof_is_rejected(result),
    }
    verification_seconds = time.perf_counter() - verification_started
    if not report.ok or not all(negative_tests.values()):
        raise RuntimeError(
            f"party {party_id} public verification failed: {report}, {negative_tests}"
        )

    serialization_started = time.perf_counter()
    srs = build_srs(result, already_verified=True)
    srs_path = write_srs(srs, args.output_srs)
    serialization_seconds = time.perf_counter() - serialization_started
    # Match run_local's metric boundary: the independent external Go check is
    # reported separately and is not part of ceremony end-to-end latency.
    end_to_end_seconds = time.perf_counter() - end_to_end_started
    kzg_result = None
    if args.kzg_smoke:
        from .kzg_smoke import run_kzg_smoke

        kzg_result = run_kzg_smoke(srs_path, timeout_seconds=args.timeout)

    success = (
        report.ok
        and all(negative_tests.values())
        and transport["curve_denied_count"] == 0
        and transport["invalid_auth_metadata_count"] == 0
        and transport["identity_spoofing_count"] == 0
        and (kzg_result is None or kzg_result["ok"])
    )
    record = {
        "format": METRICS_FORMAT,
        "party_id": party_id,
        "params": params.as_dict(),
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
                None if kzg_result is None else kzg_result["elapsed_seconds"]
            ),
        },
        "verification": asdict(report),
        "negative_tests": negative_tests,
        "transport": transport,
        "pending_protocol_tasks": result.pending_protocol_tasks,
        "artifact": {
            "path": str(srs_path.resolve()),
            "digest": srs.digest,
            "size_bytes": srs.encoded_size_bytes,
            "requested_powers": srs.requested_powers,
            "effective_powers": srs.effective_powers,
        },
        "continuum_kzg_smoke": kzg_result,
    }
    _write_json(args.metrics_output, record)
    print(RESULT_MARKER + json.dumps(record, sort_keys=True, separators=(",", ":")))
    return 0 if success else 1


def main() -> int:
    return asyncio.run(async_main(parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
