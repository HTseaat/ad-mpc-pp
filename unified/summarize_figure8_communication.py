#!/usr/bin/env python3
"""Normalize local Figure 8 communication artifacts under one byte profile.

The local campaign executes one representative layer of the homogeneous
all-linear circuit. This tool preserves measured sender-side message
multiplicity, normalizes Continuum's decimal cryptographic payloads to the
same fixed-width representation used by AD-MPC, and reports communication per
computation layer. Input distribution and final output reconstruction are not
selected by the experiment runners.
"""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

try:
    from unified.analyze_protocol_overhead import analyze_documents, load_documents
    from unified.canonical_communication import (
        AGGTRANS_PROOF_BYTES,
        FIELD_BYTES,
        G1_BYTES,
        PROFILE,
        SYMMETRIC_CIPHERTEXT_OVERHEAD,
        canonical_admpc_binary_result,
        computation_layer_result,
        profile_metadata,
        stripe_bytes,
    )
except ModuleNotFoundError:  # Direct execution puts unified/ itself on sys.path.
    from analyze_protocol_overhead import analyze_documents, load_documents
    from canonical_communication import (
        AGGTRANS_PROOF_BYTES,
        FIELD_BYTES,
        G1_BYTES,
        PROFILE,
        SYMMETRIC_CIPHERTEXT_OVERHEAD,
        canonical_admpc_binary_result,
        computation_layer_result,
        profile_metadata,
        stripe_bytes,
    )


SCHEMA = "figure8-canonical-communication-summary-v2"
AUDIT_SCHEMA = "figure8-canonical-normalization-audit-v1"
PARAMETERS = ((4, 1), (10, 3), (16, 5), (22, 7))
BATCH_SIZE = 100
PUBLIC_TUPLE_OVERHEAD = {"retransmit": 36, "cached": 29}
PROTOCOLS = ("admpc", "continuum_aggtrans", "continuum_noagg")
SOURCE_PATHS = (
    "unified/analyze_protocol_overhead.py",
    "unified/canonical_communication.py",
    "unified/run_figure8_admpc_local.sh",
    "unified/run_figure8_admpc_communication_local.sh",
    "unified/run_figure8_aggtrans_local.sh",
    "unified/run_figure8_aggtrans_communication_local.sh",
    "unified/run_figure8_communication_case.sh",
    "unified/run_figure8_local_case.sh",
    "unified/run_figure8_noagg_local.sh",
    "unified/run_figure8_noagg_communication_local.sh",
    "unified/run_figure8_one_layer_case.sh",
    "unified/run_admpc_local.sh",
    "unified/run_continuum_local.sh",
    "unified/summarize_figure8_communication.py",
    "admpc/scripts/admpc_dynamic_linear_run.py",
    "admpc/adkg/acss.py",
    "admpc/adkg/ipc.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_linear_run.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/aggregation_interfaces.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/hbacss.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/ipc.py",
)


class SummaryError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise SummaryError(message)


def _artifact_set_hash(paths):
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _source_hashes(workspace_root):
    result = {}
    for relative in SOURCE_PATHS:
        path = workspace_root / relative
        _require(path.is_file(), f"missing source file {relative}")
        result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _analyze_case(
    case_dir, expected_variant, expected_processes, n, t, batch_size,
):
    raw_dir = case_dir / "raw"
    paths = sorted(raw_dir.glob("communication-*.json"))
    _require(
        len(paths) == expected_processes,
        f"{case_dir}: expected {expected_processes} artifacts, got {len(paths)}",
    )
    documents = load_documents(raw_dir)
    summary, _, _, _ = analyze_documents(documents)
    _require(summary["protocol_variant"] == expected_variant,
             f"{case_dir}: variant mismatch")
    parameters = summary["parameters"]
    _require(int(parameters["committee_size"]) == n, f"{case_dir}: n mismatch")
    _require(int(parameters["threshold"]) == t, f"{case_dir}: t mismatch")
    _require(int(parameters["expected_batch_size"]) == batch_size,
             f"{case_dir}: batch mismatch")
    _require(int(parameters["expected_operations"]) == 1,
             f"{case_dir}: expected one computation layer")
    _require(summary["communication_complete"] is True,
             f"{case_dir}: communication is incomplete")
    persisted_path = case_dir / "analysis" / "summary.json"
    _require(persisted_path.is_file(), f"{case_dir}: persisted analysis missing")
    persisted = json.loads(persisted_path.read_text(encoding="utf-8"))
    for field in (
        "system_total_payload_bytes", "system_total_messages",
        "normalization_count", "component_bytes", "tag_totals",
    ):
        _require(persisted[field] == summary[field],
                 f"{case_dir}: stale analysis field {field}")
    return documents, summary, {
        "artifact_count": len(paths),
        "artifact_set_sha256": _artifact_set_hash(paths),
        "communication_complete": True,
    }


def _continuum_calibration(documents, summary, protocol, n, t):
    parameters = summary["parameters"]
    _require(parameters.get("cryptographic_payload_encoding") == "decimal-json",
             f"{protocol}: source encoding metadata missing")
    _require(parameters.get("canonical_communication_profile") == PROFILE,
             f"{protocol}: canonical profile mismatch")
    if protocol == "aggtrans":
        _require(
            str(parameters.get("agg_kzg_mode", "")).strip().lower()
            in {"1", "true", "yes", "on", "v2"},
            "AggTrans canonical results require AGG_KZG_V2=1",
        )
    records = [
        record
        for document in documents
        for record in document.get("payload_calibrations", [])
        if record.get("protocol") == protocol
    ]
    records.sort(key=lambda record: int(record["dealer_local_id"]))
    _require(len(records) == n, f"expected {n} {protocol} calibrations")
    _require(
        [int(record["dealer_local_id"]) for record in records] == list(range(n)),
        f"{protocol}: dealer calibration IDs are incomplete",
    )
    _require(
        all(len(record["private_ciphertext_bytes"]) == n for record in records),
        f"{protocol}: private calibration matrix is incomplete",
    )
    code_k = t + 1
    public_body = sum(
        n * n * stripe_bytes(record["public_payload_bytes"], code_k)
        for record in records
    )
    private_body = sum(
        (2 * n - 1) * sum(
            stripe_bytes(ciphertext, code_k)
            for ciphertext in record["private_ciphertext_bytes"]
        )
        for record in records
    )
    observed = int(summary["system_total_payload_bytes"])
    control = observed - public_body - private_body
    _require(control >= 0, f"{protocol}: calibrated bodies exceed observed total")
    return {
        "erasure_code_k": code_k,
        "observed_public_body_bytes": public_body,
        "observed_private_body_bytes": private_body,
        "measured_protocol_control_and_envelope_bytes": control,
    }


def canonical_continuum(
    *, n, t, circuit_depth, control_bytes, variant,
    old_commitments="retransmit", batch_size=BATCH_SIZE,
):
    _require(variant in {"aggtrans", "aggtrans-noagg"}, "bad variant")
    _require(old_commitments in PUBLIC_TUPLE_OVERHEAD,
             "bad old commitment policy")
    if variant == "aggtrans":
        public_vectors = 2 if old_commitments == "retransmit" else 1
        common_proof = AGGTRANS_PROOF_BYTES
    else:
        public_vectors = 5 if old_commitments == "retransmit" else 4
        common_proof = 0
    public_payload = (
        public_vectors * batch_size * G1_BYTES
        + common_proof
        + G1_BYTES
        + PUBLIC_TUPLE_OVERHEAD[old_commitments]
    )
    private_ciphertext = (
        batch_size * (G1_BYTES + 2 * FIELD_BYTES)
        + SYMMETRIC_CIPHERTEXT_OVERHEAD
    )
    code_k = t + 1
    public_body = n * n * n * stripe_bytes(public_payload, code_k)
    private_body = (
        n * (2 * n - 1) * n * stripe_bytes(private_ciphertext, code_k)
    )
    components = {
        "canonical_public_rbc_body": public_body,
        "canonical_private_avid_body": private_body,
        "protocol_control_and_envelopes": int(control_bytes),
    }
    return computation_layer_result(
        sum(components.values()),
        batch_size=batch_size,
        unit="sharing",
        circuit_depth=circuit_depth,
        components=components,
    )


def build_report(
    campaign_root, circuit_depth=6, old_commitments="retransmit",
    parameters=None, protocols=None, batch_size=BATCH_SIZE,
):
    campaign_root = Path(campaign_root).resolve()
    _require(campaign_root.is_dir(), f"campaign root missing: {campaign_root}")
    _require(int(circuit_depth) > 0, "circuit depth must be positive")
    _require(int(batch_size) > 0, "batch size must be positive")
    batch_size = int(batch_size)
    selected_parameters = tuple(parameters or PARAMETERS)
    selected_protocols = tuple(protocols or PROTOCOLS)
    _require(selected_protocols, "at least one protocol must be selected")
    _require(
        len(set(selected_protocols)) == len(selected_protocols),
        "protocol selections must be unique",
    )
    _require(
        set(selected_protocols) <= set(PROTOCOLS),
        "unknown Figure 8 protocol selection",
    )
    cases = []
    audit_cases = []
    for n, t in selected_parameters:
        base = campaign_root / f"n{n}_t{t}"
        summaries = {}
        integrity = {}
        calibrations = {}
        normalized = {}
        if "admpc" in selected_protocols:
            _, ad_summary, integrity["admpc"] = _analyze_case(
                base / "admpc-linear", "admpc-linear", 3 * n, n, t,
                batch_size,
            )
            summaries["admpc"] = ad_summary
            normalized["admpc"] = canonical_admpc_binary_result(
                ad_summary,
                expected_components={"randgen", "adtrans"},
                batch_size=batch_size,
                unit="sharing",
                circuit_depth=circuit_depth,
            )
        if "continuum_aggtrans" in selected_protocols:
            agg_docs, agg_summary, integrity["continuum_aggtrans"] = (
                _analyze_case(
                    base / "continuum-aggtrans", "aggtrans", 3 * n, n, t,
                    batch_size,
                )
            )
            summaries["continuum_aggtrans"] = agg_summary
            calibrations["aggtrans"] = _continuum_calibration(
                agg_docs, agg_summary, "aggtrans", n, t
            )
            normalized["continuum_aggtrans"] = canonical_continuum(
                n=n, t=t, circuit_depth=circuit_depth,
                control_bytes=calibrations["aggtrans"][
                    "measured_protocol_control_and_envelope_bytes"
                ],
                variant="aggtrans", old_commitments=old_commitments,
                batch_size=batch_size,
            )
        if "continuum_noagg" in selected_protocols:
            noagg_docs, noagg_summary, integrity["continuum_noagg"] = (
                _analyze_case(
                    base / "continuum-noagg", "aggtrans-noagg", 3 * n, n, t,
                    batch_size,
                )
            )
            summaries["continuum_noagg"] = noagg_summary
            calibrations["noagg"] = _continuum_calibration(
                noagg_docs, noagg_summary, "aggtrans-noagg", n, t
            )
            normalized["continuum_noagg"] = canonical_continuum(
                n=n, t=t, circuit_depth=circuit_depth,
                control_bytes=calibrations["noagg"][
                    "measured_protocol_control_and_envelope_bytes"
                ],
                variant="aggtrans-noagg", old_commitments=old_commitments,
                batch_size=batch_size,
            )
        comparison = {}
        if "admpc" in normalized and "continuum_aggtrans" in normalized:
            ad = normalized["admpc"]["canonical_bytes_per_computation_layer"]
            agg = normalized["continuum_aggtrans"][
                "canonical_bytes_per_computation_layer"
            ]
            comparison["continuum_aggtrans_reduction_vs_admpc_percent"] = (
                1 - agg / ad
            ) * 100
        if "admpc" in normalized and "continuum_noagg" in normalized:
            ad = normalized["admpc"]["canonical_bytes_per_computation_layer"]
            noagg = normalized["continuum_noagg"][
                "canonical_bytes_per_computation_layer"
            ]
            comparison["continuum_noagg_reduction_vs_admpc_percent"] = (
                1 - noagg / ad
            ) * 100
        if (
            "continuum_aggtrans" in normalized
            and "continuum_noagg" in normalized
        ):
            agg = normalized["continuum_aggtrans"][
                "canonical_bytes_per_computation_layer"
            ]
            noagg = normalized["continuum_noagg"][
                "canonical_bytes_per_computation_layer"
            ]
            comparison["continuum_aggtrans_reduction_vs_noagg_percent"] = (
                1 - agg / noagg
            ) * 100
        case_report = {
            "n": n,
            "t": t,
            "adtrans_alg4_mode": (
                summaries["admpc"]["parameters"]["adtrans_alg4_mode"]
                if "admpc" in summaries else None
            ),
            "canonical": normalized,
        }
        if comparison:
            case_report["comparison"] = comparison
        cases.append(case_report)
        audit_cases.append({
            "n": n,
            "t": t,
            "integrity": integrity,
            "continuum_calibration": calibrations,
        })
    adtrans_modes = {
        case["adtrans_alg4_mode"]
        for case in cases
        if case["adtrans_alg4_mode"] is not None
    }
    _require(
        len(adtrans_modes) <= 1,
        "ADTrans mode differs between committee sizes",
    )
    workspace_root = Path(__file__).resolve().parents[1]
    report = {
        "schema": SCHEMA,
        "metric": {
            "name": "canonical sender-side application bytes per computation layer",
            "self_send_included": False,
            "input_distribution_included": False,
            "final_output_reconstruction_included": False,
        },
        "experiment": {
            "figure": 8,
            "circuit": "all-linear",
            "batch_size": batch_size,
            "circuit_depth": int(circuit_depth),
            "measurement_basis": "one representative computation layer",
            "protocols": list(selected_protocols),
        },
        "canonical_serialization": profile_metadata(),
        "cases": cases,
    }
    audit = {
        "schema": AUDIT_SCHEMA,
        "campaign_root": str(campaign_root),
        "source_sha256": _source_hashes(workspace_root),
        "cases": audit_cases,
    }
    return report, audit


def render_csv(report):
    output = io.StringIO()
    fields = (
        "figure", "circuit", "n", "t", "adtrans_alg4_mode", "protocol",
        "canonical_bytes_per_computation_layer", "canonical_bytes_per_sharing",
    )
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for case in report["cases"]:
        for protocol, result in case["canonical"].items():
            writer.writerow({
                "figure": 8,
                "circuit": "all-linear",
                "n": case["n"],
                "t": case["t"],
                "adtrans_alg4_mode": case["adtrans_alg4_mode"],
                "protocol": protocol,
                "canonical_bytes_per_computation_layer": result[
                    "canonical_bytes_per_computation_layer"
                ],
                "canonical_bytes_per_sharing": result[
                    "canonical_bytes_per_sharing"
                ],
            })
    return output.getvalue()


def render_markdown(report):
    lines = [
        "# Figure 8 canonical communication",
        "",
        "All-linear circuit; sender-side application communication for one "
        "computation layer. Input distribution and final output reconstruction "
        "are excluded.",
        "",
        "| n | t | ADTrans mode | protocol | canonical B/layer | B/sharing |",
        "|---:|---:|:---|:---|---:|---:|",
    ]
    labels = {
        "admpc": "AD-MPC",
        "continuum_aggtrans": "Continuum AggTrans",
        "continuum_noagg": "Continuum NoAgg",
    }
    for case in report["cases"]:
        for protocol in PROTOCOLS:
            if protocol not in case["canonical"]:
                continue
            result = case["canonical"][protocol]
            lines.append(
                "| {n} | {t} | {mode} | {protocol} | {layer:,} | {unit:,.2f} |".format(
                    n=case["n"], t=case["t"],
                    mode=case["adtrans_alg4_mode"] or "n/a",
                    protocol=labels[protocol],
                    layer=result["canonical_bytes_per_computation_layer"],
                    unit=result["canonical_bytes_per_sharing"],
                )
            )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_root")
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument(
        "--case", dest="cases", action="append", nargs=2, type=int,
        metavar=("N", "T"),
    )
    parser.add_argument(
        "--old-commitments", choices=("retransmit", "cached"),
        default="retransmit",
    )
    parser.add_argument(
        "--protocol", choices=PROTOCOLS, action="append", dest="protocols",
    )
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        report, audit = build_report(
            args.campaign_root,
            circuit_depth=args.depth,
            old_commitments=args.old_commitments,
            parameters=args.cases,
            protocols=args.protocols,
            batch_size=args.batch_size,
        )
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "summary.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (output_dir / "summary.csv").write_text(
            render_csv(report), encoding="utf-8"
        )
        markdown = render_markdown(report)
        (output_dir / "summary.md").write_text(markdown, encoding="utf-8")
        (output_dir / "normalization_audit.json").write_text(
            json.dumps(audit, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError) as exc:
        parser.exit(2, f"figure8 communication summary failed: {exc}\n")
    print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
