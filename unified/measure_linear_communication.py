#!/usr/bin/env python3
"""Audit local linear-handoff communication for Continuum and AD-MPC.

The tool deliberately separates two questions:

* ``implementation`` reports the currently observed serialized payload bytes;
* ``paper`` projects the messages required by the two papers using canonical
  binary group/field sizes and the locally calibrated dissemination behavior.

It does not start sockets or distributed workers.  A calibration profile
contains auditable local measurements, while all reported totals are derived
from the profile's raw phase and payload-size entries.
"""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import sys


SCHEMA = "linear-communication-calibration-v1"
DEFAULT_PROFILE = (
    Path(__file__).resolve().parent
    / "communication_models"
    / "linear_n4_t1_b100.json"
)
PROTOCOLS = ("continuum", "admpc")
MODES = ("implementation", "paper")


class CommunicationModelError(ValueError):
    """Raised when a calibration is incomplete or used out of scope."""


def _require(condition, message):
    if not condition:
        raise CommunicationModelError(message)


def _positive_int(value, name):
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise CommunicationModelError(f"{name} must be an integer") from exc
    _require(normalized > 0, f"{name} must be positive")
    return normalized


def _validate_source_hashes(profile):
    expected_hashes = profile.get("source_sha256")
    _require(expected_hashes, "calibration is missing source_sha256")
    workspace_root = Path(__file__).resolve().parents[1]
    problems = []
    for relative_path, expected_hash in sorted(expected_hashes.items()):
        source = workspace_root / relative_path
        try:
            actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError:
            problems.append(f"missing {relative_path}")
            continue
        if actual_hash != expected_hash:
            problems.append(f"changed {relative_path}")
    _require(
        not problems,
        "calibration source check failed ({})".format(", ".join(problems)),
    )
    return {"checked": True, "files": len(expected_hashes), "matches": True}


def load_profile(path=DEFAULT_PROFILE, check_source_hashes=True):
    profile_path = Path(path)
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CommunicationModelError(
            f"cannot load calibration profile {profile_path}: {exc}"
        ) from exc
    _require(profile.get("schema") == SCHEMA, "unsupported calibration schema")
    for section in ("metric", "parameters", "serialization", "continuum", "admpc"):
        _require(section in profile, f"calibration is missing {section!r}")
    profile["_path"] = str(profile_path.resolve())
    if check_source_hashes:
        profile["_source_status"] = _validate_source_hashes(profile)
    else:
        profile["_source_status"] = {
            "checked": False,
            "files": len(profile.get("source_sha256", {})),
            "matches": None,
        }
    return profile


def _stripe_bytes(payload_bytes, code_k):
    """Match the repository's encode input: payload // k plus one pad byte."""
    return payload_bytes // code_k + 1


def _base_result(protocol, mode, components, n, batch_size, depth, confidence, notes):
    per_transfer = sum(components.values())
    total = per_transfer * depth
    logical_processes = n * (depth + 2)
    return {
        "protocol": protocol,
        "mode": mode,
        "confidence": confidence,
        "components_per_transfer": components,
        "per_transfer_payload_bytes": per_transfer,
        "transfer_count": depth,
        "total_payload_bytes": total,
        "normalization_unit": "sharing",
        "normalization_count": batch_size * depth,
        "bytes_per_sharing": total / (batch_size * depth),
        "logical_process_count": logical_processes,
        "average_bytes_per_logical_process": total / logical_processes,
        "notes": notes,
    }


def _continuum_implementation(profile, n, batch_size, depth):
    implementation = profile["continuum"]["implementation"]
    transport = profile["continuum"]["transport"]
    public_sizes = implementation["rbc_payload_bytes_by_dealer"]
    private_sizes = implementation["private_ciphertext_bytes_by_dealer"]
    _require(len(public_sizes) == n, "wrong number of Continuum public dealer payloads")
    _require(len(private_sizes) == n, "wrong number of Continuum private dealer payload sets")
    _require(
        all(len(dealer_payloads) == n for dealer_payloads in private_sizes),
        "each Continuum dealer must have one private ciphertext per receiver",
    )
    k = _positive_int(transport["erasure_code_k"], "erasure_code_k")
    rbc_multiplier = _positive_int(
        transport["rbc_stripe_transmissions_per_dealer"],
        "rbc_stripe_transmissions_per_dealer",
    )
    avid_multiplier = _positive_int(
        transport["avid_stripe_transmission_multiplier"],
        "avid_stripe_transmission_multiplier",
    )
    public_body = sum(
        rbc_multiplier * _stripe_bytes(payload, k) for payload in public_sizes
    )
    private_body = sum(
        avid_multiplier
        * sum(_stripe_bytes(payload, k) for payload in dealer_payloads)
        for dealer_payloads in private_sizes
    )
    observed = _positive_int(
        implementation["observed_remote_payload_bytes_per_transfer"],
        "observed_remote_payload_bytes_per_transfer",
    )
    control = observed - public_body - private_body
    _require(control >= 0, "Continuum payload bodies exceed the observed total")
    return _base_result(
        "continuum",
        "implementation",
        {
            "public_rbc_body": public_body,
            "private_avid_body": private_body,
            "control_and_serialization_envelopes": control,
        },
        n,
        batch_size,
        depth,
        "locally observed",
        [
            "Current JSON/pickle encoding is retained.",
            "Common old commitments and aggregate proofs are duplicated in receiver-private ciphertexts.",
        ],
    )


def _continuum_paper(profile, n, batch_size, depth, old_commitments):
    serialization = profile["serialization"]
    paper = profile["continuum"]["paper"]
    transport = profile["continuum"]["transport"]
    g1 = _positive_int(serialization["g1_bytes"], "g1_bytes")
    field = _positive_int(serialization["field_bytes"], "field_bytes")
    cipher_overhead = _positive_int(
        serialization["symmetric_ciphertext_overhead_bytes"],
        "symmetric_ciphertext_overhead_bytes",
    )
    if old_commitments == "retransmit":
        commitment_vectors = 2
        tuple_overhead = _positive_int(
            serialization["public_tuple_overhead_retransmit_bytes"],
            "public_tuple_overhead_retransmit_bytes",
        )
    else:
        commitment_vectors = 1
        tuple_overhead = _positive_int(
            serialization["public_tuple_overhead_cached_bytes"],
            "public_tuple_overhead_cached_bytes",
        )
    public_payload = (
        commitment_vectors * batch_size * g1
        + _positive_int(
            paper["aggregated_public_proof_bytes"],
            "aggregated_public_proof_bytes",
        )
        + _positive_int(
            paper["ephemeral_public_key_bytes"],
            "ephemeral_public_key_bytes",
        )
        + tuple_overhead
    )
    # One evaluation proof and two field shares per transferred sharing.
    private_plaintext = batch_size * (g1 + 2 * field)
    private_ciphertext = private_plaintext + cipher_overhead
    k = _positive_int(transport["erasure_code_k"], "erasure_code_k")
    rbc_multiplier = _positive_int(
        transport["rbc_stripe_transmissions_per_dealer"],
        "rbc_stripe_transmissions_per_dealer",
    )
    avid_multiplier = _positive_int(
        transport["avid_stripe_transmission_multiplier"],
        "avid_stripe_transmission_multiplier",
    )
    public_body = n * rbc_multiplier * _stripe_bytes(public_payload, k)
    private_body = (
        n * avid_multiplier * n * _stripe_bytes(private_ciphertext, k)
    )
    control = _positive_int(
        paper["control_and_tag_overhead_bytes_per_transfer"],
        "control_and_tag_overhead_bytes_per_transfer",
    )
    return _base_result(
        "continuum",
        "paper",
        {
            "public_rbc_body": public_body,
            "private_avid_body": private_body,
            "calibrated_control_and_tag_overhead": control,
        },
        n,
        batch_size,
        depth,
        "paper-faithful calibrated projection",
        [
            f"Old commitment policy: {old_commitments}.",
            "Cryptographic fields use canonical binary sizes; public data is broadcast once.",
            "Control/tag overhead is retained from the local implementation calibration.",
        ],
    )


def _admpc_implementation(profile, n, batch_size, depth):
    implementation = profile["admpc"]["implementation"]
    bundle = _positive_int(
        implementation["batch_bundle_bytes_per_transfer"],
        "batch_bundle_bytes_per_transfer",
    )
    adtrans = _positive_int(
        implementation["adtrans_bytes_per_transfer"],
        "adtrans_bytes_per_transfer",
    )
    rand_executed = bool(implementation["batch_rand_executed_by_linear_driver"])
    _require(not rand_executed, "profile unexpectedly marks current BatchRand as executed")
    return _base_result(
        "admpc",
        "implementation",
        {
            "batch_bundle": bundle,
            "batch_rand_omitted_by_driver": 0,
            "adtrans_with_aggregated_public_fields": adtrans,
        },
        n,
        batch_size,
        depth,
        "locally observed",
        [
            "The active linear driver executes BatchBundle but omits the independent BatchRand required by the paper.",
            "ADTrans aggregates B public mask/proof fields into one tuple.",
        ],
    )


def _admpc_paper(profile, n, batch_size, depth):
    serialization = profile["serialization"]
    implementation = profile["admpc"]["implementation"]
    paper = profile["admpc"]["paper"]
    g1 = _positive_int(serialization["g1_bytes"], "g1_bytes")
    field = _positive_int(serialization["field_bytes"], "field_bytes")
    public_item = (
        _positive_int(
            paper["public_fields_per_item_g1_elements"],
            "public_fields_per_item_g1_elements",
        )
        * g1
        + _positive_int(
            paper["public_fields_per_item_field_elements"],
            "public_fields_per_item_field_elements",
        )
        * field
    )
    # Current ADTrans sends one aggregated tuple where Algorithm 4 sends B tuples.
    public_broadcast_restoration = n * n * public_item * (batch_size - 1)
    bundle = _positive_int(
        implementation["batch_bundle_bytes_per_transfer"],
        "batch_bundle_bytes_per_transfer",
    )
    batch_rand = _positive_int(
        paper["batch_rand_bytes_per_transfer"],
        "batch_rand_bytes_per_transfer",
    )
    current_adtrans = _positive_int(
        implementation["adtrans_bytes_per_transfer"],
        "adtrans_bytes_per_transfer",
    )
    return _base_result(
        "admpc",
        "paper",
        {
            "batch_rand": batch_rand,
            "batch_bundle": bundle,
            "adtrans_current_body_and_control": current_adtrans,
            "adtrans_per_item_public_broadcast_restoration": public_broadcast_restoration,
        },
        n,
        batch_size,
        depth,
        "paper-faithful measured plus derived correction",
        [
            "Includes the independent BatchRand and BatchBundle phases required by AD-MPC.",
            "Restores per-item m, m-hat, omega, and W public fields from Algorithm 4.",
        ],
    )


def calculate(
    profile,
    n,
    t,
    batch_size,
    depth,
    mode="both",
    protocol="all",
    old_commitments="retransmit",
):
    n = _positive_int(n, "n")
    t = int(t)
    _require(t >= 0, "t must be non-negative")
    batch_size = _positive_int(batch_size, "batch_size")
    depth = _positive_int(depth, "depth")
    calibrated = profile["parameters"]
    requested = {"n": n, "t": t, "batch_size": batch_size}
    expected = {
        "n": int(calibrated["n"]),
        "t": int(calibrated["t"]),
        "batch_size": int(calibrated["batch_size"]),
    }
    _require(
        requested == expected,
        "no exact local calibration for n={n}, t={t}, B={batch_size}; "
        "this profile supports n={en}, t={et}, B={eb}".format(
            **requested,
            en=expected["n"],
            et=expected["t"],
            eb=expected["batch_size"],
        ),
    )
    _require(mode in ("both",) + MODES, f"unsupported mode {mode!r}")
    _require(protocol in ("all",) + PROTOCOLS, f"unsupported protocol {protocol!r}")
    _require(
        old_commitments in ("retransmit", "cached"),
        "old_commitments must be retransmit or cached",
    )
    selected_modes = MODES if mode == "both" else (mode,)
    selected_protocols = PROTOCOLS if protocol == "all" else (protocol,)
    builders = {
        ("continuum", "implementation"): _continuum_implementation,
        ("admpc", "implementation"): _admpc_implementation,
    }
    results = {}
    for selected_mode in selected_modes:
        results[selected_mode] = {}
        for selected_protocol in selected_protocols:
            if selected_mode == "paper" and selected_protocol == "continuum":
                result = _continuum_paper(
                    profile, n, batch_size, depth, old_commitments
                )
            elif selected_mode == "paper":
                result = _admpc_paper(profile, n, batch_size, depth)
            else:
                result = builders[(selected_protocol, selected_mode)](
                    profile, n, batch_size, depth
                )
            results[selected_mode][selected_protocol] = result
    comparisons = {}
    for selected_mode, mode_results in results.items():
        if set(mode_results) == set(PROTOCOLS):
            continuum = mode_results["continuum"]["per_transfer_payload_bytes"]
            admpc = mode_results["admpc"]["per_transfer_payload_bytes"]
            comparisons[selected_mode] = {
                "admpc_over_continuum_ratio": admpc / continuum,
                "continuum_reduction_vs_admpc_percent": (1 - continuum / admpc) * 100,
            }
    return {
        "schema": "linear-communication-audit-v1",
        "metric": profile["metric"],
        "calibration_profile": profile["_path"],
        "calibration_source_status": profile["_source_status"],
        "parameters": {
            "n": n,
            "t": t,
            "batch_size": batch_size,
            "depth": depth,
            "old_commitments": old_commitments,
        },
        "results": results,
        "comparisons": comparisons,
    }


def _format_int(value):
    return f"{int(value):,}"


def render_table(report):
    lines = [
        "Metric: " + report["metric"]["name"],
        "Parameters: n={n}, t={t}, B={batch_size}, d={depth}, old_commitments={old_commitments}".format(
            **report["parameters"]
        ),
    ]
    for mode, protocols in report["results"].items():
        lines.extend(("", f"[{mode}]"))
        for protocol, result in protocols.items():
            lines.append(f"{protocol}")
            for phase, value in result["components_per_transfer"].items():
                lines.append(f"  {phase:<48} {_format_int(value):>14} B")
            lines.append(
                f"  {'per transfer':<48} {_format_int(result['per_transfer_payload_bytes']):>14} B"
            )
            lines.append(
                f"  {'bytes per sharing':<48} {result['bytes_per_sharing']:>14,.2f} B"
            )
            lines.append(
                f"  {('d=' + str(result['transfer_count']) + ' total'):<48} "
                f"{_format_int(result['total_payload_bytes']):>14} B"
            )
        comparison = report["comparisons"].get(mode)
        if comparison:
            lines.append(
                "comparison: AD-MPC/Continuum={:.4f}x; Continuum reduction={:.2f}%".format(
                    comparison["admpc_over_continuum_ratio"],
                    comparison["continuum_reduction_vs_admpc_percent"],
                )
            )
    return "\n".join(lines) + "\n"


def _flat_rows(report):
    rows = []
    for mode, protocols in report["results"].items():
        for protocol, result in protocols.items():
            rows.append({
                **report["parameters"],
                "mode": mode,
                "protocol": protocol,
                "per_transfer_payload_bytes": result["per_transfer_payload_bytes"],
                "transfer_count": result["transfer_count"],
                "total_payload_bytes": result["total_payload_bytes"],
                "bytes_per_sharing": result["bytes_per_sharing"],
                "average_bytes_per_logical_process": result[
                    "average_bytes_per_logical_process"
                ],
                "components_per_transfer": json.dumps(
                    result["components_per_transfer"], sort_keys=True
                ),
                "confidence": result["confidence"],
            })
    return rows


def render_csv(report):
    rows = _flat_rows(report)
    output = io.StringIO()
    fields = [
        "mode",
        "protocol",
        "n",
        "t",
        "batch_size",
        "depth",
        "old_commitments",
        "per_transfer_payload_bytes",
        "transfer_count",
        "total_payload_bytes",
        "bytes_per_sharing",
        "average_bytes_per_logical_process",
        "components_per_transfer",
        "confidence",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def render(report, output_format):
    if output_format == "json":
        return json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output_format == "csv":
        return render_csv(report)
    return render_table(report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE))
    parser.add_argument("--protocol", choices=("all",) + PROTOCOLS, default="all")
    parser.add_argument("--mode", choices=("both",) + MODES, default="both")
    parser.add_argument("--n", type=int, default=4)
    parser.add_argument("--t", type=int, default=1)
    parser.add_argument("--batch", type=int, default=100)
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument(
        "--old-commitments",
        choices=("retransmit", "cached"),
        default="retransmit",
        help="whether Continuum retransmits the old C^l vector (default: retransmit)",
    )
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--output", help="also write the selected output to this path")
    parser.add_argument(
        "--allow-stale-calibration",
        action="store_true",
        help="skip source SHA-256 checks (the output will record that hashes were not checked)",
    )
    args = parser.parse_args(argv)
    try:
        profile = load_profile(
            args.profile, check_source_hashes=not args.allow_stale_calibration
        )
        report = calculate(
            profile,
            n=args.n,
            t=args.t,
            batch_size=args.batch,
            depth=args.depth,
            mode=args.mode,
            protocol=args.protocol,
            old_commitments=args.old_commitments,
        )
        rendered = render(report, args.format)
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(rendered, encoding="utf-8")
    except CommunicationModelError as exc:
        print(f"linear communication audit failed: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
