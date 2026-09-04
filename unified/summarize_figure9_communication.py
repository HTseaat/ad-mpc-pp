#!/usr/bin/env python3
"""Normalize local Figure 9 communication artifacts under one byte profile.

The local campaign executes one representative layer of the homogeneous
all-multiplication circuit. AD-MPC is counted from its integrated nonlinear
driver; in particular, BatchRand executed inside ADPrep is already included
in the AP tag and no standalone BatchRand result is added afterwards.
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
        PRODUCT_PROOF_BYTES,
        PROFILE,
        SYMMETRIC_CIPHERTEXT_OVERHEAD,
        canonical_admpc_binary_result,
        computation_layer_result,
        profile_metadata,
        stripe_bytes,
    )
except ModuleNotFoundError:
    from analyze_protocol_overhead import analyze_documents, load_documents
    from canonical_communication import (
        AGGTRANS_PROOF_BYTES,
        FIELD_BYTES,
        G1_BYTES,
        PRODUCT_PROOF_BYTES,
        PROFILE,
        SYMMETRIC_CIPHERTEXT_OVERHEAD,
        canonical_admpc_binary_result,
        computation_layer_result,
        profile_metadata,
        stripe_bytes,
    )


SCHEMA = "figure9-canonical-communication-summary-v2"
AUDIT_SCHEMA = "figure9-canonical-normalization-audit-v1"
PARAMETERS = ((4, 1), (10, 3), (16, 5), (22, 7))
BATCH_SIZE = 100
PUBLIC_TUPLE_OVERHEAD = {"aggtrans": 36, "batchmul": 69, "bgw": 42}
PROTOCOLS = ("admpc", "continuum_batchmul", "bgw_aggtrans")
SOURCE_PATHS = (
    "unified/analyze_protocol_overhead.py",
    "unified/canonical_communication.py",
    "unified/run_figure9_admpc_communication_local.sh",
    "unified/run_figure9_admpc_local.sh",
    "unified/run_figure9_batchmul_communication_local.sh",
    "unified/run_figure9_batchmul_local.sh",
    "unified/run_figure9_bgw_aggtrans_communication_local.sh",
    "unified/run_figure9_bgw_aggtrans_local.sh",
    "unified/run_figure9_communication_case.sh",
    "unified/run_figure9_local_case.sh",
    "unified/run_figure9_one_layer_case.sh",
    "unified/run_admpc_local.sh",
    "unified/run_continuum_local.sh",
    "unified/summarize_figure9_communication.py",
    "admpc/scripts/admpc_dynamic_nonlinear_run.py",
    "admpc/adkg/admpc_dynamic.py",
    "admpc/adkg/aprep.py",
    "admpc/adkg/acss.py",
    "admpc/adkg/ipc.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_nonlinear_run.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_bgw_aggtrans_run.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/hbacss.py",
    "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/ipc.py",
)


class SummaryError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise SummaryError(message)


def _file_set_hash(paths, root):
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(root)).encode("utf-8"))
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
    case_dir, expected_variant, expected_processes, n, t,
    batch_size=BATCH_SIZE,
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
    logs = sorted((case_dir / "logs").glob("*.log"))
    _require(len(logs) in {0, expected_processes},
             f"{case_dir}: incomplete log set")
    return documents, summary, {
        "artifact_count": len(paths),
        "artifact_set_sha256": _file_set_hash(paths, raw_dir),
        "communication_complete": True,
        "log_count": len(logs),
    }


def _payload_calibration(
    documents, observed_bytes, protocol, n, t, topology,
    require_batch=False, batch_size=BATCH_SIZE,
):
    parameters = documents[0]["parameters"]
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
    if require_batch:
        _require(
            all(int(record.get("batch_size", -1)) == batch_size
                for record in records),
            f"{protocol}: calibration batch mismatch",
        )
    code_k = n - 2 * t
    _require(code_k == t + 1,
             f"unexpected erasure parameter for n={n}, t={t}")
    if topology == "dynamic":
        public_multiplier = n * n
        private_multiplier = 2 * n - 1
    elif topology == "static":
        public_multiplier = n * n - 1
        private_multiplier = 2 * (n - 1)
    else:
        raise SummaryError(f"unknown topology {topology}")
    public_body = sum(
        public_multiplier * stripe_bytes(record["public_payload_bytes"], code_k)
        for record in records
    )
    private_body = sum(
        private_multiplier * sum(
            stripe_bytes(ciphertext, code_k)
            for ciphertext in record["private_ciphertext_bytes"]
        )
        for record in records
    )
    control = int(observed_bytes) - public_body - private_body
    _require(control >= 0, f"{protocol}: calibrated bodies exceed observed total")
    calibration = {
        "topology": topology,
        "erasure_code_k": code_k,
        "observed_public_body_bytes": public_body,
        "observed_private_body_bytes": private_body,
        "measured_protocol_control_and_envelope_bytes": control,
    }
    if protocol == "batchmul":
        proof_sizes = {int(record["factor_proof_bytes"]) for record in records}
        _require(len(proof_sizes) == 1,
                 "BatchMul factor proof sizes differ by dealer")
        calibration["factor_proof_bytes"] = proof_sizes.pop()
    if protocol == "bgw":
        proof_counts = {int(record["product_proof_count"]) for record in records}
        _require(proof_counts == {batch_size},
                 "BGW product proof count mismatch")
        calibration["product_proof_count"] = proof_counts.pop()
    return calibration


def _canonical_payload_sizes(
    protocol, factor_proof_bytes=None, batch_size=BATCH_SIZE,
):
    private_ciphertext = (
        batch_size * (G1_BYTES + 2 * FIELD_BYTES)
        + SYMMETRIC_CIPHERTEXT_OVERHEAD
    )
    if protocol == "aggtrans":
        public_payload = (
            2 * batch_size * G1_BYTES
            + AGGTRANS_PROOF_BYTES
            + G1_BYTES
            + PUBLIC_TUPLE_OVERHEAD[protocol]
        )
    elif protocol == "batchmul":
        _require(factor_proof_bytes is not None,
                 "missing BatchMul factor proof size")
        public_payload = (
            6 * batch_size * G1_BYTES
            + 4 * G1_BYTES
            + int(factor_proof_bytes)
            + PUBLIC_TUPLE_OVERHEAD[protocol]
        )
    elif protocol == "bgw":
        public_payload = (
            (4 * batch_size + 3) * G1_BYTES
            + batch_size * PRODUCT_PROOF_BYTES
            + PUBLIC_TUPLE_OVERHEAD[protocol]
        )
    else:
        raise SummaryError(f"unknown protocol {protocol}")
    return public_payload, private_ciphertext


def _canonical_hbacss(
    protocol, n, t, circuit_depth, calibration, topology,
    batch_size=BATCH_SIZE,
):
    public_payload, private_ciphertext = _canonical_payload_sizes(
        protocol, calibration.get("factor_proof_bytes"), batch_size
    )
    code_k = n - 2 * t
    if topology == "dynamic":
        public_multiplier = n * n
        private_multiplier = 2 * n - 1
    else:
        public_multiplier = n * n - 1
        private_multiplier = 2 * (n - 1)
    public_body = n * public_multiplier * stripe_bytes(public_payload, code_k)
    private_body = (
        n * private_multiplier * n * stripe_bytes(private_ciphertext, code_k)
    )
    components = {
        "canonical_public_rbc_body": public_body,
        "canonical_private_avid_body": private_body,
        "protocol_control_and_envelopes": int(
            calibration["measured_protocol_control_and_envelope_bytes"]
        ),
    }
    return computation_layer_result(
        sum(components.values()),
        batch_size=batch_size,
        unit="gate",
        circuit_depth=circuit_depth,
        components=components,
    )


def build_report(
    campaign_root, circuit_depth=6, parameters=None, protocols=None,
    batch_size=BATCH_SIZE,
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
        "unknown Figure 9 protocol selection",
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
                base / "admpc-nonlinear", "admpc-nonlinear", 3 * n, n, t,
                batch_size,
            )
            summaries["admpc"] = ad_summary
            normalized["admpc"] = canonical_admpc_binary_result(
                ad_summary,
                expected_components={"adprep", "randgen", "exec", "adtrans"},
                batch_size=batch_size,
                unit="gate",
                circuit_depth=circuit_depth,
            )

        if "continuum_batchmul" in selected_protocols:
            mul_docs, mul_summary, integrity["continuum_batchmul"] = (
                _analyze_case(
                    base / "continuum-batchmul", "batchmul", 3 * n, n, t,
                    batch_size,
                )
            )
            summaries["continuum_batchmul"] = mul_summary
            calibrations["batchmul"] = _payload_calibration(
                mul_docs, mul_summary["component_bytes"]["batchmul"],
                "batchmul", n, t, "dynamic", require_batch=True,
                batch_size=batch_size,
            )
            normalized["continuum_batchmul"] = _canonical_hbacss(
                "batchmul", n, t, circuit_depth,
                calibrations["batchmul"], "dynamic", batch_size,
            )

        if "bgw_aggtrans" in selected_protocols:
            bgw_docs, bgw_summary, integrity["bgw_aggtrans"] = _analyze_case(
                base / "bgw-aggtrans", "bgw-aggtrans", 3 * n, n, t,
                batch_size,
            )
            summaries["bgw_aggtrans"] = bgw_summary
            calibrations["bgw"] = _payload_calibration(
                bgw_docs, bgw_summary["component_bytes"]["bgw"],
                "bgw", n, t, "static", require_batch=True,
                batch_size=batch_size,
            )
            calibrations["aggtrans"] = _payload_calibration(
                bgw_docs, bgw_summary["component_bytes"]["aggtrans"],
                "aggtrans", n, t, "dynamic", batch_size=batch_size,
            )
            bgw = _canonical_hbacss(
                "bgw", n, t, circuit_depth, calibrations["bgw"], "static",
                batch_size,
            )
            aggtrans = _canonical_hbacss(
                "aggtrans", n, t, circuit_depth,
                calibrations["aggtrans"], "dynamic", batch_size,
            )
            bgw_agg_components = {
                "canonical_bgw": bgw["canonical_bytes_per_computation_layer"],
                "canonical_aggtrans": aggtrans[
                    "canonical_bytes_per_computation_layer"
                ],
            }
            normalized["bgw_aggtrans"] = computation_layer_result(
                sum(bgw_agg_components.values()),
                batch_size=batch_size,
                unit="gate",
                circuit_depth=circuit_depth,
                components=bgw_agg_components,
            )

        comparison = {}
        if "admpc" in normalized and "continuum_batchmul" in normalized:
            ad_bytes = normalized["admpc"][
                "canonical_bytes_per_computation_layer"
            ]
            mul_bytes = normalized["continuum_batchmul"][
                "canonical_bytes_per_computation_layer"
            ]
            comparison["continuum_batchmul_reduction_vs_admpc_percent"] = (
                1 - mul_bytes / ad_bytes
            ) * 100
        if "admpc" in normalized and "bgw_aggtrans" in normalized:
            ad_bytes = normalized["admpc"][
                "canonical_bytes_per_computation_layer"
            ]
            bgw_bytes = normalized["bgw_aggtrans"][
                "canonical_bytes_per_computation_layer"
            ]
            comparison["bgw_aggtrans_reduction_vs_admpc_percent"] = (
                1 - bgw_bytes / ad_bytes
            ) * 100
        if (
            "continuum_batchmul" in normalized
            and "bgw_aggtrans" in normalized
        ):
            mul_bytes = normalized["continuum_batchmul"][
                "canonical_bytes_per_computation_layer"
            ]
            bgw_bytes = normalized["bgw_aggtrans"][
                "canonical_bytes_per_computation_layer"
            ]
            comparison[
                "continuum_batchmul_reduction_vs_bgw_aggtrans_percent"
            ] = (1 - mul_bytes / bgw_bytes) * 100

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
            "adprep_nested_batchrand_included": True,
            "standalone_batchrand_added": False,
        },
        "experiment": {
            "figure": 9,
            "circuit": "all-multiplication",
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
        "canonical_bytes_per_computation_layer", "canonical_bytes_per_gate",
    )
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for case in report["cases"]:
        for protocol, result in case["canonical"].items():
            writer.writerow({
                "figure": 9,
                "circuit": "all-multiplication",
                "n": case["n"],
                "t": case["t"],
                "adtrans_alg4_mode": case["adtrans_alg4_mode"],
                "protocol": protocol,
                "canonical_bytes_per_computation_layer": result[
                    "canonical_bytes_per_computation_layer"
                ],
                "canonical_bytes_per_gate": result[
                    "canonical_bytes_per_gate"
                ],
            })
    return output.getvalue()


def render_markdown(report):
    lines = [
        "# Figure 9 canonical communication",
        "",
        "All-multiplication circuit; sender-side application communication "
        "for one computation layer. Input distribution and final output "
        "reconstruction are excluded. ADPrep's integrated BatchRand is included; "
        "no standalone BatchRand measurement is added.",
        "",
        "| n | t | ADTrans mode | protocol | canonical B/layer | B/gate |",
        "|---:|---:|:---|:---|---:|---:|",
    ]
    labels = {
        "admpc": "AD-MPC",
        "continuum_batchmul": "Continuum BatchMul",
        "bgw_aggtrans": "BGW-AggTrans",
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
                    unit=result["canonical_bytes_per_gate"],
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
        "--protocol", choices=PROTOCOLS, action="append", dest="protocols",
    )
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        report, audit = build_report(
            args.campaign_root,
            circuit_depth=args.depth,
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
        parser.exit(2, f"figure9 communication summary failed: {exc}\n")
    print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
