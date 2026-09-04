"""Run stages 1--6/8/9 over an in-memory asynchronous committee."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from dataclasses import asdict
from pathlib import Path

from .config import SetupParams, load_committee_config_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path)
    parser.add_argument("--n", type=int)
    parser.add_argument("--t", type=int)
    parser.add_argument("--powers", type=int)
    parser.add_argument("--run-id")
    parser.add_argument("--timeout", default=180.0, type=float)
    parser.add_argument("--output-srs", type=Path)
    parser.add_argument("--metrics-output", type=Path)
    parser.add_argument(
        "--kzg-smoke",
        action="store_true",
        help="run the standalone Continuum Go KZG smoke test (requires --output-srs)",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def params_from_args(args: argparse.Namespace) -> SetupParams:
    direct_values = (args.n, args.t, args.powers, args.run_id)
    if args.config_dir is not None:
        if any(value is not None for value in direct_values):
            raise ValueError("--config-dir cannot be combined with direct parameters")
        configs = load_committee_config_dir(args.config_dir)
        return configs[0].params
    if any(value is None for value in direct_values):
        raise ValueError("direct mode requires --n, --t, --powers, and --run-id")
    return SetupParams.create(args.n, args.t, args.powers, run_id=args.run_id)


async def async_main(args: argparse.Namespace) -> int:
    params = params_from_args(args)
    if args.kzg_smoke and args.output_srs is None:
        raise ValueError("--kzg-smoke requires --output-srs")

    # Delay native imports until after pure parameter/config validation.
    from .protocol.distributed_tau import run_local_setup
    from .protocol.verification import (
        mismatched_alpha_h_chain_is_rejected,
        tamper_is_rejected,
        tampered_dleq_proof_is_rejected,
        tampered_h_chain_is_rejected,
        tampered_h_commitment_is_rejected,
        verify_result,
    )

    end_to_end_started = time.perf_counter()
    result = await run_local_setup(params, timeout_seconds=args.timeout)
    verification_started = time.perf_counter()
    report = verify_result(result)
    tamper_rejected = tamper_is_rejected(result)
    h_tamper_rejected = tampered_h_commitment_is_rejected(result)
    proof_tamper_rejected = tampered_dleq_proof_is_rejected(result)
    h_chain_tamper_rejected = tampered_h_chain_is_rejected(result)
    mismatched_alpha_rejected = mismatched_alpha_h_chain_is_rejected(result)
    verification_seconds = time.perf_counter() - verification_started
    negative_tests = {
        "g_chain_tamper_rejected": tamper_rejected,
        "h_commitment_tamper_rejected": h_tamper_rejected,
        "dleq_proof_tamper_rejected": proof_tamper_rejected,
        "h_chain_tamper_rejected": h_chain_tamper_rejected,
        "mismatched_alpha_h_chain_rejected": mismatched_alpha_rejected,
    }

    srs = None
    srs_path = None
    serialization_seconds = 0.0
    kzg_result = None
    if args.output_srs is not None and report.ok and all(negative_tests.values()):
        from .serialization import build_srs, write_srs

        serialization_started = time.perf_counter()
        srs = build_srs(result, already_verified=True)
        srs_path = write_srs(srs, args.output_srs)
        serialization_seconds = time.perf_counter() - serialization_started
    end_to_end_seconds = time.perf_counter() - end_to_end_started
    if args.kzg_smoke and srs_path is not None:
        from .kzg_smoke import run_kzg_smoke

        kzg_result = run_kzg_smoke(srs_path, timeout_seconds=args.timeout)
    summary = {
        "params": params.as_dict(),
        "elapsed_seconds": result.elapsed_seconds,
        "end_to_end_elapsed_seconds": end_to_end_seconds,
        "base_link_elapsed_seconds": result.base_link_elapsed_seconds,
        "g_all_powers_elapsed_seconds": result.g_all_powers_elapsed_seconds,
        "h_all_powers_elapsed_seconds": result.h_all_powers_elapsed_seconds,
        "setup_elapsed_seconds": result.setup_elapsed_seconds,
        "squaring_elapsed_seconds": result.squaring_elapsed_seconds,
        "g2_powers_elapsed_seconds": result.g2_powers_elapsed_seconds,
        "verification_seconds": verification_seconds,
        "serialization_seconds": serialization_seconds,
        "party_count": len(result.parties),
        "g_chain_length": len(result.parties[0].g_chain),
        "h_chain_length": len(result.parties[0].h_chain),
        "g2_exported": True,
        "h_powers_of_two_count": len(result.parties[0].powers_of_two_h1),
        "alpha_g2_agreement": report.all_parties_same_g2,
        "verification": asdict(report),
        "tamper_rejected": tamper_rejected,
        "h_tamper_rejected": h_tamper_rejected,
        "dleq_proof_tamper_rejected": proof_tamper_rejected,
        "h_chain_tamper_rejected": h_chain_tamper_rejected,
        "mismatched_alpha_h_chain_rejected": mismatched_alpha_rejected,
        "sent_bytes_per_party": list(result.sent_bytes_per_party),
        "sent_bytes_median": statistics.median(result.sent_bytes_per_party),
        "sent_bytes_max": max(result.sent_bytes_per_party),
        "srs": (
            None
            if srs is None
            else {
                "path": str(srs_path.resolve()),
                "digest": srs.digest,
                "size_bytes": srs.encoded_size_bytes,
            }
        ),
        "continuum_kzg_smoke": kzg_result,
        "ok": (
            report.ok
            and tamper_rejected
            and h_tamper_rejected
            and proof_tamper_rejected
            and h_chain_tamper_rejected
            and mismatched_alpha_rejected
            and (kzg_result is None or kzg_result["ok"])
        ),
    }
    if args.metrics_output is not None:
        from .metrics import build_metrics_record, write_metrics

        metrics = build_metrics_record(
            result=result,
            verification=summary["verification"],
            negative_tests=negative_tests,
            end_to_end_seconds=end_to_end_seconds,
            verification_seconds=verification_seconds,
            serialization_seconds=serialization_seconds,
            srs=srs,
            srs_path=srs_path,
            kzg_smoke=kzg_result,
        )
        write_metrics(metrics, args.metrics_output)
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "trusted setup stages 1--5: "
            f"n={params.n}, t={params.t}, "
            f"requested_powers={params.requested_powers}, "
            f"effective_powers={params.effective_powers}, log_q={params.log_q}"
        )
        print(
            f"elapsed={result.elapsed_seconds:.6f}s, parties={len(result.parties)}, "
            f"g_chain={len(result.parties[0].g_chain)}, "
            f"h_chain={len(result.parties[0].h_chain)}, g2_exported=yes, "
            f"base_link={result.base_link_elapsed_seconds:.6f}s"
        )
        print(
            f"sent bytes/party median={summary['sent_bytes_median']}, "
            f"max={summary['sent_bytes_max']}"
        )
        print(
            f"algebraic/pairing verification={'PASS' if report.ok else 'FAIL'}, "
            f"chain tamper={'PASS' if tamper_rejected else 'FAIL'}, "
            f"H tamper={'PASS' if h_tamper_rejected else 'FAIL'}, "
            f"DLEQ tamper={'PASS' if proof_tamper_rejected else 'FAIL'}, "
            f"h-chain tamper={'PASS' if h_chain_tamper_rejected else 'FAIL'}, "
            f"wrong-alpha h-chain={'PASS' if mismatched_alpha_rejected else 'FAIL'}"
        )
        if srs is not None:
            print(
                f"SRS={srs_path}, size={srs.encoded_size_bytes} bytes, "
                f"digest={srs.digest}"
            )
        if kzg_result is not None:
            print("Continuum Go KZG smoke=PASS")
    return 0 if summary["ok"] else 1


def main() -> int:
    args = parse_args()
    return asyncio.run(async_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
