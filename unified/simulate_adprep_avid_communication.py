#!/usr/bin/env python3
"""Communication-only ADprep simulation with RBC + AVID transport.

This script performs no field, commitment, proof, encryption, or erasure-code
computation.  It calibrates the already measured ADprep proposal sizes from the
source-party AP counters, then serializes deterministic placeholder messages
with the same tuple/list layout as Continuum's dynamic RBC and AVID good path.

Metric: len(pickle.dumps(message, protocol=4)) for every remote application
message.  Self sends, receives, CURVE setup, ZeroMQ, TCP, and IP framing are not
counted.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import pickle
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA = "adprep-rbc-avid-communication-simulation-v1"
PICKLE_PROTOCOL = 4
BATCH_SIZE = 100
DEPTH = 6
CASES = ((4, 1), (10, 3), (16, 5), (22, 7))

DEFAULT_LOCAL_ROOT = Path(
    "/opt/benchmark-local/figure9-paper-communication-20260823T035300Z"
)
DEFAULT_N22_LOG_ROOT = Path(
    "/opt/benchmark-distributed/aws-public-fig9-n22-admpc-overhead-20260821/"
    "20260821T013755Z_admpc_exp2/n22_t7_d6/logs"
)

SOURCE_CODE_PATHS = (
    Path("/opt/admpc/adkg/acss.py"),
    Path("/opt/admpc/adkg/aprep.py"),
    Path("/opt/admpc/adkg/rand.py"),
    Path("/opt/admpc/adkg/broadcast/optqrbc.py"),
    Path("/opt/admpc/adkg/ipc.py"),
    Path(
        "/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/broadcast/"
        "reliablebroadcast.py"
    ),
    Path(
        "/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/broadcast/avid.py"
    ),
)


class SimulationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SimulationError(message)


def _pickle_size(message: object) -> int:
    return len(pickle.dumps(message, protocol=PICKLE_PROTOCOL))


def _stripe_bytes(payload_bytes: int, code_k: int) -> int:
    """Match zfec encode padding, including a full block on exact division."""
    _require(payload_bytes >= 0, "negative payload length")
    _require(code_k > 0, "non-positive erasure-code k")
    return payload_bytes // code_k + 1


def _public_payload_bytes(poly_count: int) -> int:
    """Current log-ACSS public proposal without its receiver ciphertexts.

    commits: 48*p; shared: 2+32+2*32+48+48*p; ephemeral key: 48.
    """
    return 96 * int(poly_count) + 194


def _rand_poly_count(n: int, t: int) -> int:
    # This simulator calibrates the archived pre-fix campaign, whose
    # BatchRand implementation produced n-t outputs per BACSS batch.
    return math.ceil(n * BATCH_SIZE / (n - t))


def _instance_prefix(
    source_layer: int, dealer: int, instance: str, channel_message: object
) -> object:
    if instance == "main":
        return (f"AP.A{source_layer}{dealer}", channel_message)
    if instance == "rand":
        return ("AP.GR", (f"GR.A{source_layer}{dealer}", channel_message))
    raise SimulationError(f"unknown ADprep ACSS instance: {instance}")


def _wire_message(
    source_layer: int,
    dealer: int,
    target_layer: int,
    instance: str,
    channel_tag: str,
    body: object,
) -> object:
    """Reproduce the empty runner tag plus AP/ACSS/channel wrap_send stack."""
    channel_message = (channel_tag, body)
    prefixed = _instance_prefix(source_layer, dealer, instance, channel_message)
    return ("", (f"AP{target_layer}", prefixed))


def _current_rbc_tag(dealer: int, target_layer: int) -> str:
    return f"{dealer}-0-{target_layer}-B-RBC"


def _new_avid_tag(dealer: int, target_layer: int) -> str:
    return f"{dealer}-0-{target_layer}-B-AVID"


def _current_message(
    source_layer: int,
    dealer: int,
    target_layer: int,
    instance: str,
    message_type: int,
    payload: bytes,
) -> object:
    tag = _current_rbc_tag(dealer, target_layer)
    return _wire_message(
        source_layer, dealer, target_layer, instance, tag,
        (message_type, payload),
    )


def infer_combined_private_ciphertext_bytes(
    source_bytes: int,
    n: int,
    t: int,
    source_layer: int,
    dealer: int,
    target_layer: int,
) -> Mapping[str, int]:
    """Invert a completed source's two optqrbc broadcasts.

    A completed source emits, per destination, two PROPOSE messages and
    ECHO+READY for each proposal.  The two proposal pickle sizes are affine in
    their byte payloads, so their combined raw length is recoverable without
    knowing the split between main ADprep and its nested Rand instance.
    """
    _require(source_bytes % n == 0, "source AP bytes are not n identical sends")
    digest = bytes(32)
    controls_per_destination = sum(
        _pickle_size(
            _current_message(
                source_layer, dealer, target_layer, instance, message_type, digest
            )
        )
        for instance in ("main", "rand")
        for message_type in (2, 3)
    )
    dummy_length = 100_000
    proposal_pickle_overhead = sum(
        _pickle_size(
            _current_message(
                source_layer,
                dealer,
                target_layer,
                instance,
                1,
                bytes(dummy_length),
            )
        )
        - dummy_length
        for instance in ("main", "rand")
    )
    raw_proposals = (
        source_bytes // n - controls_per_destination - proposal_pickle_overhead
    )
    public_bytes = _public_payload_bytes(6 * BATCH_SIZE) + _public_payload_bytes(
        _rand_poly_count(n, t)
    )
    private_block = raw_proposals - public_bytes
    _require(private_block > 0, "inferred private ciphertext block is empty")
    _require(
        private_block % n == 0,
        "proposal calibration does not divide into n equal ciphertext pairs",
    )
    per_receiver = private_block // n
    _require(
        per_receiver % 16 == 0,
        "combined AES-CBC ciphertext length is not a multiple of 16",
    )
    return {
        "source_bytes": int(source_bytes),
        "controls_per_destination_bytes": controls_per_destination,
        "proposal_pickle_overhead_bytes": proposal_pickle_overhead,
        "combined_raw_proposal_bytes": raw_proposals,
        "combined_public_payload_bytes": public_bytes,
        "combined_private_ciphertext_bytes_per_receiver": per_receiver,
    }


def _minimum_ciphertext_bytes(poly_count: int) -> int:
    """Safe lower bound from phis + t_hats and AES-CBC IV/padding alone."""
    # Both vectors contain poly_count 32-byte field elements.  Their 64*p byte
    # subtotal is block aligned, so CBC adds at least one pad block plus the IV.
    return 64 * poly_count + 32


def private_split_stripe_bounds(
    combined_ciphertext_bytes: int, n: int, t: int
) -> Mapping[str, Mapping[str, int]]:
    """Find exact stripe-sum bounds over all feasible AES block-aligned splits."""
    main_polys = 6 * BATCH_SIZE
    rand_polys = _rand_poly_count(n, t)
    main_min = _minimum_ciphertext_bytes(main_polys)
    rand_min = _minimum_ciphertext_bytes(rand_polys)
    _require(
        combined_ciphertext_bytes >= main_min + rand_min,
        "combined ciphertext is smaller than its serialized field vectors",
    )
    code_k = t + 1
    candidates: Dict[int, Tuple[int, int]] = {}
    proportional_main = (
        combined_ciphertext_bytes * main_polys / (main_polys + rand_polys)
    )
    first = ((main_min + 15) // 16) * 16
    last = combined_ciphertext_bytes - ((rand_min + 15) // 16) * 16
    for main_bytes in range(first, last + 1, 16):
        rand_bytes = combined_ciphertext_bytes - main_bytes
        if rand_bytes < rand_min or rand_bytes % 16:
            continue
        stripe_sum = _stripe_bytes(main_bytes, code_k) + _stripe_bytes(
            rand_bytes, code_k
        )
        previous = candidates.get(stripe_sum)
        if previous is None or abs(main_bytes - proportional_main) < abs(
            previous[0] - proportional_main
        ):
            # The bound depends only on stripe_sum.  Choosing the candidate
            # closest to the public poly-count ratio makes the representative
            # split readable without claiming that it is the measured split.
            candidates[stripe_sum] = (main_bytes, rand_bytes)
    _require(candidates, "no feasible AES-aligned main/Rand ciphertext split")
    low_sum, high_sum = min(candidates), max(candidates)

    def record(stripe_sum: int) -> Mapping[str, int]:
        main_bytes, rand_bytes = candidates[stripe_sum]
        return {
            "main_ciphertext_bytes": main_bytes,
            "rand_ciphertext_bytes": rand_bytes,
            "main_stripe_bytes": _stripe_bytes(main_bytes, code_k),
            "rand_stripe_bytes": _stripe_bytes(rand_bytes, code_k),
            "combined_stripe_bytes": stripe_sum,
        }

    return {"lower": record(low_sum), "upper": record(high_sum)}


def _private_pickle_frame_uncertainty_per_handoff(n: int) -> int:
    """Conservative bound for protocol-4 FRAME changes across private splits.

    Bytes objects below/above pickle's 64 KiB framing threshold have the same
    opcode/header length, but can change where nine-byte FRAME headers appear.
    An AVID VAL has n variable stripe objects, so changing their lengths can
    affect at most n+2 frames. A RESPONSE has one variable stripe and can
    affect at most two. There are 2*n^2 serialized VALs and
    2*n^2*(n-1) serialized remote RESPONSEs across the two ACSS instances.
    """
    return 18 * n * n * (n + 2) + 36 * n * n * (n - 1)


def _blob(length: int, seed: str) -> bytes:
    """Return deterministic, non-cryptographic placeholder bytes."""
    _require(length >= 0, "negative placeholder size")
    if length == 0:
        return b""
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return (digest * ((length + len(digest) - 1) // len(digest)))[:length]


def _hashes(count: int, seed: str) -> List[bytes]:
    # Each call yields distinct bytes objects, matching separately built trees
    # and avoiding accidental pickle memoization of one shared placeholder.
    return [_blob(32, f"{seed}:{index}") for index in range(count)]


@dataclass
class Traffic:
    bytes_by_category: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    messages_by_category: Dict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )

    def add(self, category: str, message: object, multiplicity: int = 1) -> None:
        _require(multiplicity >= 0, "negative message multiplicity")
        self.bytes_by_category[category] += _pickle_size(message) * multiplicity
        self.messages_by_category[category] += multiplicity

    @property
    def total_bytes(self) -> int:
        return sum(self.bytes_by_category.values())

    @property
    def total_messages(self) -> int:
        return sum(self.messages_by_category.values())

    def grouped_bytes(self) -> Mapping[str, int]:
        public = sum(
            value
            for name, value in self.bytes_by_category.items()
            if name.startswith("public_rbc_")
        )
        private = sum(
            value
            for name, value in self.bytes_by_category.items()
            if name.startswith("private_avid_")
        )
        return {
            "public_rbc": public,
            "private_avid": private,
            "rbc_avid_total": public + private,
        }


def _wrap_new(
    source_layer: int,
    dealer: int,
    target_layer: int,
    instance: str,
    channel_tag: str,
    body: object,
) -> object:
    return _wire_message(
        source_layer, dealer, target_layer, instance, channel_tag, body
    )


def simulate_rbc_avid_transport(
    n: int,
    t: int,
    source_layer: int,
    target_layer: int,
    main_ciphertext_bytes: int,
    rand_ciphertext_bytes: int,
) -> Traffic:
    """Serialize the all-honest dynamic RBC+AVID good-path messages."""
    code_k = t + 1
    branch_height = math.ceil(math.log2(n))
    traffic = Traffic()
    instance_inputs = {
        "main": (6 * BATCH_SIZE, main_ciphertext_bytes),
        "rand": (_rand_poly_count(n, t), rand_ciphertext_bytes),
    }

    for dealer in range(n):
        for instance, (poly_count, ciphertext_bytes) in instance_inputs.items():
            seed = f"{n}:{source_layer}:{dealer}:{instance}"

            # Public block: dynamic erasure-coded RBC.  The source sends n VALs;
            # each destination sends ECHO and READY to n-1 remote destinations.
            rbc_tag = _current_rbc_tag(dealer, target_layer)
            public_stripe = _stripe_bytes(
                _public_payload_bytes(poly_count), code_k
            )
            rbc_root = _blob(32, seed + ":rbc-root")
            rbc_branch = _hashes(branch_height, seed + ":rbc-branch")
            rbc_stripe = _blob(public_stripe, seed + ":rbc-stripe")
            rbc_val_body = (rbc_tag, "VAL", rbc_root, rbc_branch, rbc_stripe)
            rbc_echo_body = (rbc_tag, "ECHO", rbc_root, rbc_branch, rbc_stripe)
            rbc_ready_body = (rbc_tag, "READY", rbc_root)
            traffic.add(
                "public_rbc_val",
                _wrap_new(
                    source_layer, dealer, target_layer, instance, rbc_tag,
                    rbc_val_body,
                ),
                n,
            )
            traffic.add(
                "public_rbc_echo",
                _wrap_new(
                    source_layer, dealer, target_layer, instance, rbc_tag,
                    rbc_echo_body,
                ),
                n * (n - 1),
            )
            traffic.add(
                "public_rbc_ready",
                _wrap_new(
                    source_layer, dealer, target_layer, instance, rbc_tag,
                    rbc_ready_body,
                ),
                n * (n - 1),
            )

            # Private receiver ciphertexts: AVID VAL contains one stripe for
            # every receiver.  ECHO/READY are controls.  Each receiver asks all
            # other destination members for its item; they answer with a stripe.
            avid_tag = _new_avid_tag(dealer, target_layer)
            private_stripe = _stripe_bytes(ciphertext_bytes, code_k)
            roots = _hashes(n, seed + ":avid-roots")
            branches = [
                _hashes(branch_height, seed + f":avid-branch:{receiver}")
                for receiver in range(n)
            ]
            stripes = [
                _blob(private_stripe, seed + f":avid-stripe:{receiver}")
                for receiver in range(n)
            ]
            avid_val_body = (avid_tag, "VAL", roots, branches, stripes)
            avid_echo_body = (avid_tag, "ECHO")
            avid_ready_body = (avid_tag, "READY")
            avid_retrieve_body = (avid_tag, "RETRIEVE", 0)
            avid_response_body = (
                avid_tag, "RESPONSE", 0, roots[0], stripes[0]
            )
            traffic.add(
                "private_avid_val",
                _wrap_new(
                    source_layer, dealer, target_layer, instance, avid_tag,
                    avid_val_body,
                ),
                n,
            )
            for category, body in (
                ("private_avid_echo", avid_echo_body),
                ("private_avid_ready", avid_ready_body),
                ("private_avid_retrieve", avid_retrieve_body),
                ("private_avid_response", avid_response_body),
            ):
                traffic.add(
                    category,
                    _wrap_new(
                        source_layer, dealer, target_layer, instance, avid_tag,
                        body,
                    ),
                    n * (n - 1),
                )
    return traffic


def current_destination_optqrbc_traffic(
    n: int, source_layer: int, target_layer: int
) -> Traffic:
    """Current follower ECHO/READY bytes replaced by the new transport."""
    traffic = Traffic()
    digest = bytes(32)
    for dealer in range(n):
        for instance in ("main", "rand"):
            for message_type, name in ((2, "echo"), (3, "ready")):
                traffic.add(
                    f"current_optqrbc_{name}",
                    _current_message(
                        source_layer,
                        dealer,
                        target_layer,
                        instance,
                        message_type,
                        digest,
                    ),
                    n * n,
                )
    return traffic


def _sha256_paths(paths: Iterable[Path], relative_to: Optional[Path] = None) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        name = str(path.relative_to(relative_to)) if relative_to else str(path)
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass(frozen=True)
class HandoffMeasurement:
    source_layer: int
    target_layer: int
    measured_bytes: int
    measured_messages: Optional[int]
    source_bytes: int
    source_messages: Optional[int]


@dataclass(frozen=True)
class CaseMeasurement:
    n: int
    t: int
    handoffs: Tuple[HandoffMeasurement, ...]
    calibration: Mapping[str, int]
    input_kind: str
    input_path: str
    input_count: int
    input_sha256: str
    extrapolate_to_depth: bool
    audit_notes: Tuple[str, ...] = ()


def load_local_case(local_root: Path, n: int, t: int) -> CaseMeasurement:
    raw_dir = local_root / f"n{n}_t{t}" / "admpc-nonlinear" / "raw"
    paths = sorted(raw_dir.glob("communication-admpc-*.json"))
    _require(len(paths) == 3 * n, f"{raw_dir}: expected {3*n} artifacts")
    docs = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    tag = "AP1"
    measured_bytes = sum(
        int(doc["communication"]["by_tag"].get(tag, {}).get("bytes", 0))
        for doc in docs
    )
    measured_messages = sum(
        int(doc["communication"]["by_tag"].get(tag, {}).get("messages", 0))
        for doc in docs
    )
    source_docs = [doc for doc in docs if doc["process"]["physical_layer"] == 0]
    _require(len(source_docs) == n, f"{raw_dir}: source committee incomplete")
    source_bytes = sum(
        int(doc["communication"]["by_tag"][tag]["bytes"])
        for doc in source_docs
    )
    source_messages = sum(
        int(doc["communication"]["by_tag"][tag]["messages"])
        for doc in source_docs
    )
    calibrations = []
    for doc in source_docs:
        dealer = int(doc["process"]["local_party_id"])
        calibrations.append(
            infer_combined_private_ciphertext_bytes(
                int(doc["communication"]["by_tag"][tag]["bytes"]),
                n,
                t,
                0,
                dealer,
                1,
            )
        )
    private_sizes = {
        item["combined_private_ciphertext_bytes_per_receiver"]
        for item in calibrations
    }
    raw_sizes = {item["combined_raw_proposal_bytes"] for item in calibrations}
    _require(len(private_sizes) == 1, f"{raw_dir}: inconsistent private sizes")
    _require(len(raw_sizes) == 1, f"{raw_dir}: inconsistent proposal sizes")
    calibration = dict(calibrations[0])
    calibration["calibrated_dealer_count"] = len(calibrations)
    return CaseMeasurement(
        n=n,
        t=t,
        handoffs=(
            HandoffMeasurement(
                source_layer=0,
                target_layer=1,
                measured_bytes=measured_bytes,
                measured_messages=measured_messages,
                source_bytes=source_bytes,
                source_messages=source_messages,
            ),
        ),
        calibration=calibration,
        input_kind="local_completed_json_one_handoff",
        input_path=str(raw_dir),
        input_count=len(paths),
        input_sha256=_sha256_paths(paths, raw_dir),
        extrapolate_to_depth=True,
    )


_GLOBAL_ID_RE = re.compile(r"^my_send_id: (\d+)\s*$", re.MULTILINE)
_AP_BYTES_RE = re.compile(r"Bytes Sent: (AP\d+):(\d+)")


def load_n22_case(log_root: Path) -> CaseMeasurement:
    n, t = 22, 7
    paths = sorted(log_root.glob("*.log"))
    _require(len(paths) == 8 * n, f"{log_root}: expected {8*n} logs")
    by_global_id: Dict[int, Mapping[str, int]] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        match = _GLOBAL_ID_RE.search(text)
        _require(match is not None, f"{path}: missing my_send_id")
        global_id = int(match.group(1))
        _require(global_id not in by_global_id, f"duplicate global id {global_id}")
        by_global_id[global_id] = {
            tag: int(value) for tag, value in _AP_BYTES_RE.findall(text)
        }
    _require(set(by_global_id) == set(range(8 * n)), "n22 global IDs incomplete")

    # Layer zero completed both source ACSS broadcasts and is the clean payload
    # calibration point.  Later source checkpoints are audited below.
    layer_zero = []
    for dealer in range(n):
        source_bytes = int(by_global_id[dealer]["AP1"])
        layer_zero.append(
            infer_combined_private_ciphertext_bytes(
                source_bytes, n, t, 0, dealer, 1
            )
        )
    private_sizes = {
        item["combined_private_ciphertext_bytes_per_receiver"] for item in layer_zero
    }
    raw_sizes = {item["combined_raw_proposal_bytes"] for item in layer_zero}
    _require(len(private_sizes) == 1, "n22 layer-zero private sizes disagree")
    _require(len(raw_sizes) == 1, "n22 layer-zero proposal sizes disagree")
    calibration = dict(layer_zero[0])
    calibration["calibrated_dealer_count"] = n

    handoffs = []
    deficits = []
    raw_proposals = int(calibration["combined_raw_proposal_bytes"])
    dummy_length = 100_000
    for source_layer in range(DEPTH):
        target_layer = source_layer + 1
        tag = f"AP{target_layer}"
        measured = sum(
            int(tags.get(tag, 0)) for tags in by_global_id.values()
        )
        source = sum(
            int(by_global_id[source_layer * n + dealer][tag])
            for dealer in range(n)
        )
        handoffs.append(
            HandoffMeasurement(
                source_layer=source_layer,
                target_layer=target_layer,
                measured_bytes=measured,
                measured_messages=None,
                source_bytes=source,
                source_messages=None,
            )
        )

        expected_source = 0
        expected_one_main_control = 0
        for dealer in range(n):
            proposal_overhead = sum(
                _pickle_size(
                    _current_message(
                        source_layer,
                        dealer,
                        target_layer,
                        instance,
                        1,
                        bytes(dummy_length),
                    )
                )
                - dummy_length
                for instance in ("main", "rand")
            )
            controls = sum(
                _pickle_size(
                    _current_message(
                        source_layer,
                        dealer,
                        target_layer,
                        instance,
                        message_type,
                        bytes(32),
                    )
                )
                for instance in ("main", "rand")
                for message_type in (2, 3)
            )
            expected_source += n * (raw_proposals + proposal_overhead + controls)
            expected_one_main_control += n * _pickle_size(
                _current_message(
                    source_layer,
                    dealer,
                    target_layer,
                    "main",
                    3,
                    bytes(32),
                )
            )
        deficit = expected_source - source
        if source_layer == 0:
            _require(deficit == 0, "n22 layer-zero source is not complete")
        else:
            _require(
                deficit == expected_one_main_control,
                f"n22 AP{target_layer} source deficit is not one main control broadcast",
            )
        deficits.append(deficit)

    notes = (
        "AP1 source is complete; AP2-AP6 source checkpoints each omit exactly "
        "one main optqrbc READY broadcast (44,572 bytes system-wide).",
        "The omitted current control is part of measured-source replacement; "
        "the RBC+AVID simulation itself uses a complete all-honest good path.",
    )
    calibration["later_layer_source_deficit_bytes_each"] = deficits[1]
    return CaseMeasurement(
        n=n,
        t=t,
        handoffs=tuple(handoffs),
        calibration=calibration,
        input_kind="distributed_logs_six_measured_handoffs",
        input_path=str(log_root),
        input_count=len(paths),
        input_sha256=_sha256_paths(paths, log_root),
        extrapolate_to_depth=False,
        audit_notes=notes,
    )


def _evaluate_handoff(
    case: CaseMeasurement,
    handoff: HandoffMeasurement,
    split: Mapping[str, int],
) -> Mapping[str, object]:
    old_destination = current_destination_optqrbc_traffic(
        case.n, handoff.source_layer, handoff.target_layer
    )
    retained_bytes = (
        handoff.measured_bytes - handoff.source_bytes - old_destination.total_bytes
    )
    _require(retained_bytes >= 0, "negative retained measured ADprep bytes")
    retained_messages = None
    if handoff.measured_messages is not None and handoff.source_messages is not None:
        retained_messages = (
            handoff.measured_messages
            - handoff.source_messages
            - old_destination.total_messages
        )
        _require(retained_messages >= 0, "negative retained ADprep messages")

    new_transport = simulate_rbc_avid_transport(
        case.n,
        case.t,
        handoff.source_layer,
        handoff.target_layer,
        int(split["main_ciphertext_bytes"]),
        int(split["rand_ciphertext_bytes"]),
    )
    grouped = dict(new_transport.grouped_bytes())
    code_k = case.t + 1
    public_body_bytes = case.n ** 3 * (
        _stripe_bytes(_public_payload_bytes(6 * BATCH_SIZE), code_k)
        + _stripe_bytes(
            _public_payload_bytes(_rand_poly_count(case.n, case.t)), code_k
        )
    )
    private_body_bytes = (
        case.n
        * case.n
        * (2 * case.n - 1)
        * int(split["combined_stripe_bytes"])
    )
    _require(
        grouped["public_rbc"] >= public_body_bytes,
        "serialized public RBC is smaller than its stripe bodies",
    )
    _require(
        grouped["private_avid"] >= private_body_bytes,
        "serialized private AVID is smaller than its stripe bodies",
    )
    grouped["retained_measured_other_ap"] = retained_bytes
    return {
        "source_layer": handoff.source_layer,
        "target_layer": handoff.target_layer,
        "measured_current_ap_bytes": handoff.measured_bytes,
        "measured_current_ap_messages": handoff.measured_messages,
        "replaced_current_source_bytes": handoff.source_bytes,
        "replaced_current_destination_optqrbc_bytes": old_destination.total_bytes,
        "replaced_current_destination_optqrbc_messages": old_destination.total_messages,
        "retained_measured_other_ap_bytes": retained_bytes,
        "retained_measured_other_ap_messages": retained_messages,
        "simulated_rbc_avid_bytes": new_transport.total_bytes,
        "simulated_rbc_avid_messages": new_transport.total_messages,
        "simulated_total_ap_bytes": retained_bytes + new_transport.total_bytes,
        "erasure_coded_body_bytes": {
            "public_rbc_stripes": public_body_bytes,
            "private_avid_stripes": private_body_bytes,
        },
        "components_bytes": grouped,
        "transport_bytes_by_category": dict(new_transport.bytes_by_category),
        "transport_messages_by_category": dict(new_transport.messages_by_category),
    }


def evaluate_case(case: CaseMeasurement) -> Mapping[str, object]:
    combined_private = int(
        case.calibration["combined_private_ciphertext_bytes_per_receiver"]
    )
    splits = private_split_stripe_bounds(combined_private, case.n, case.t)
    bounds = {}
    for bound_name in ("lower", "upper"):
        layers = [
            _evaluate_handoff(case, handoff, splits[bound_name])
            for handoff in case.handoffs
        ]
        scale = DEPTH if case.extrapolate_to_depth else 1
        measured_d = sum(
            int(layer["measured_current_ap_bytes"]) for layer in layers
        ) * scale
        simulated_d = sum(
            int(layer["simulated_total_ap_bytes"]) for layer in layers
        ) * scale
        component_names = set().union(
            *(layer["components_bytes"].keys() for layer in layers)
        )
        components_d = {
            name: sum(
                int(layer["components_bytes"].get(name, 0)) for layer in layers
            )
            * scale
            for name in sorted(component_names)
        }
        bounds[bound_name] = {
            "private_split_representative": dict(splits[bound_name]),
            "measured_handoffs": layers,
            "depth_handoff_count": DEPTH,
            "d_total_current_ap_bytes": measured_d,
            "d_total_simulated_ap_bytes": simulated_d,
            "per_handoff_current_ap_bytes": measured_d / DEPTH,
            "per_handoff_simulated_ap_bytes": simulated_d / DEPTH,
            "d_total_components_bytes": components_d,
            "reduction_fraction": 1.0 - simulated_d / measured_d,
        }

    frame_per_handoff = _private_pickle_frame_uncertainty_per_handoff(case.n)
    frame_d = frame_per_handoff * DEPTH
    representative_lower = int(bounds["lower"]["d_total_simulated_ap_bytes"])
    representative_upper = int(bounds["upper"]["d_total_simulated_ap_bytes"])
    _require(
        representative_lower <= representative_upper,
        "split representatives are reversed",
    )
    # Stripe-byte bounds are exact. Protocol-4 FRAME placement also depends on
    # the unknown main/Rand boundary, so expand the representatives by a proven
    # frame-count bound to keep the final interval strict at the 64 KiB cutoff.
    bounds["lower"]["representative_d_total_simulated_ap_bytes"] = (
        representative_lower
    )
    bounds["upper"]["representative_d_total_simulated_ap_bytes"] = (
        representative_upper
    )
    bounds["lower"]["d_total_simulated_ap_bytes"] = representative_lower - frame_d
    bounds["upper"]["d_total_simulated_ap_bytes"] = representative_upper + frame_d
    bounds["lower"]["per_handoff_simulated_ap_bytes"] = (
        representative_lower - frame_d
    ) / DEPTH
    bounds["upper"]["per_handoff_simulated_ap_bytes"] = (
        representative_upper + frame_d
    ) / DEPTH
    bounds["lower"]["d_total_components_bytes"]["private_avid"] -= frame_d
    bounds["upper"]["d_total_components_bytes"]["private_avid"] += frame_d
    bounds["lower"]["d_total_components_bytes"]["rbc_avid_total"] -= frame_d
    bounds["upper"]["d_total_components_bytes"]["rbc_avid_total"] += frame_d
    measured_d = int(bounds["lower"]["d_total_current_ap_bytes"])
    bounds["lower"]["reduction_fraction"] = 1.0 - (
        representative_lower - frame_d
    ) / measured_d
    bounds["upper"]["reduction_fraction"] = 1.0 - (
        representative_upper + frame_d
    ) / measured_d

    lower = int(bounds["lower"]["d_total_simulated_ap_bytes"])
    upper = int(bounds["upper"]["d_total_simulated_ap_bytes"])
    _require(lower <= upper, "simulation bounds are reversed")
    max_private_uncertainty = DEPTH * case.n * case.n * (2 * case.n - 1)
    _require(
        upper - lower <= max_private_uncertainty + 2 * frame_d,
        "private split uncertainty exceeds the stripe and pickle-frame bounds",
    )
    return {
        "n": case.n,
        "t": case.t,
        "batch_size": BATCH_SIZE,
        "depth": DEPTH,
        "input": {
            "kind": case.input_kind,
            "path": case.input_path,
            "artifact_count": case.input_count,
            "artifact_set_sha256": case.input_sha256,
            "one_handoff_extrapolated_to_depth": case.extrapolate_to_depth,
        },
        "payload_calibration": dict(case.calibration),
        "split_bounds": splits,
        "bounds": bounds,
        "d_total_simulation_interval_bytes": [lower, upper],
        "simulation_interval_width_bytes": upper - lower,
        "pickle_frame_uncertainty_bound_bytes_per_handoff": frame_per_handoff,
        "audit_notes": list(case.audit_notes),
    }


def build_report(local_root: Path, n22_log_root: Path) -> Mapping[str, object]:
    measurements = [
        load_local_case(local_root, n, t) for n, t in CASES if n != 22
    ]
    measurements.append(load_n22_case(n22_log_root))
    source_hashes = {}
    for path in SOURCE_CODE_PATHS:
        _require(path.is_file(), f"missing source code input: {path}")
        source_hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "schema": SCHEMA,
        "metric": {
            "scope": "serialized application-payload bytes sent to remote parties",
            "pickle_protocol": PICKLE_PROTOCOL,
            "self_send_included": False,
            "receive_double_counted": False,
            "curve_control_included": False,
            "transport_framing_included": False,
        },
        "model": {
            "topology": "dynamic source committee to destination committee",
            "good_path": "all honest, no fallback/recovery",
            "public_transport": "Continuum dynamic erasure-coded RBC",
            "private_transport": "Continuum AVID_DYNAMIC with retrieve/response",
            "erasure_code_k": "t+1",
            "crypto_computation_executed": False,
            "retained_components": (
                "measured ADprep AP bytes outside the two current optqrbc transports"
            ),
        },
        "source_code_sha256": source_hashes,
        "cases": [evaluate_case(case) for case in measurements],
    }


def _format_interval(low: float, high: float, digits: int = 3) -> str:
    if round(low, digits) == round(high, digits):
        return f"{low:.{digits}f}"
    return f"{low:.{digits}f}-{high:.{digits}f}"


def render_markdown(report: Mapping[str, object]) -> str:
    lines = [
        "# ADprep communication-only RBC+AVID simulation",
        "",
        "No cryptographic computation was run. Existing AP measurements calibrate "
        "the two ACSS proposal sizes; deterministic placeholders are serialized "
        "through the dynamic RBC/AVID good-path message layout.",
        "",
        "Metric: `len(pickle.dumps(message, protocol=4))` for remote application "
        "messages only; no self-send, receive double count, CURVE setup, or "
        "ZeroMQ/TCP/IP framing.",
        "",
        "## Result",
        "",
        "| n | t | two ciphertexts / receiver (B) | current AP / handoff (MB) | "
        "RBC+AVID AP / handoff (MB) | saving | d=6 total (GB) |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for case in report["cases"]:
        low = case["bounds"]["lower"]
        high = case["bounds"]["upper"]
        current_mb = float(low["per_handoff_current_ap_bytes"]) / 1_000_000
        low_mb = float(low["per_handoff_simulated_ap_bytes"]) / 1_000_000
        high_mb = float(high["per_handoff_simulated_ap_bytes"]) / 1_000_000
        saving_low = float(high["reduction_fraction"]) * 100
        saving_high = float(low["reduction_fraction"]) * 100
        total_low = int(low["d_total_simulated_ap_bytes"]) / 1_000_000_000
        total_high = int(high["d_total_simulated_ap_bytes"]) / 1_000_000_000
        private_bytes = case["payload_calibration"][
            "combined_private_ciphertext_bytes_per_receiver"
        ]
        lines.append(
            f"| {case['n']} | {case['t']} | {private_bytes:,} | "
            f"{current_mb:.3f} | {_format_interval(low_mb, high_mb)} | "
            f"{_format_interval(saving_low, saving_high, 2)}% | "
            f"{_format_interval(total_low, total_high)} |"
        )

    lines.extend(
        [
            "",
            "## Simulated per-handoff breakdown",
            "",
            "| n | public RBC (MB) | private AVID (MB) | retained other AP (MB) |",
            "|---:|---:|---:|---:|",
        ]
    )
    for case in report["cases"]:
        depth = int(case["depth"])
        lower = case["bounds"]["lower"]["d_total_components_bytes"]
        upper = case["bounds"]["upper"]["d_total_components_bytes"]
        public = int(lower["public_rbc"]) / depth / 1_000_000
        private_low = int(lower["private_avid"]) / depth / 1_000_000
        private_high = int(upper["private_avid"]) / depth / 1_000_000
        retained = int(lower["retained_measured_other_ap"]) / depth / 1_000_000
        lines.append(
            f"| {case['n']} | {public:.3f} | "
            f"{_format_interval(private_low, private_high)} | {retained:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation and audit notes",
            "",
            "- `current AP` is the measured Figure 9 ADprep AP tag. The replacement "
            "subtracts the full source optqrbc bytes and the destination "
            "optqrbc ECHO/READY bytes, then adds complete dynamic RBC+AVID traffic.",
            "- Public commitments/shared proof/key are erasure-coded by RBC once. "
            "The n receiver ciphertexts are dispersed by AVID and only the requested "
            "ciphertext is reconstructed.",
            "- The logs reveal only the sum of the main and nested-Rand ciphertext "
            "lengths. Both are AES-block-aligned; enumerating every feasible stripe "
            "sum and conservatively bounding protocol-4 FRAME placement produces "
            "the reported strict interval.",
            "- n=4/10/16 use their completed local one-handoff artifacts and are "
            "extrapolated to d=6. n=22 uses six real distributed handoffs.",
        ]
    )
    for case in report["cases"]:
        for note in case.get("audit_notes", []):
            lines.append(f"- n={case['n']}: {note}")
    lines.append("")
    return "\n".join(lines)


def write_outputs(report: Mapping[str, object], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "summary.json"
    markdown_path = output_dir / "summary.md"
    csv_path = output_dir / "summary.csv"
    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "n",
                "t",
                "batch_size",
                "depth",
                "combined_private_ciphertext_bytes_per_receiver",
                "current_ap_bytes_per_handoff",
                "simulated_ap_bytes_per_handoff_lower",
                "simulated_ap_bytes_per_handoff_upper",
                "reduction_fraction_lower",
                "reduction_fraction_upper",
                "d_total_simulated_bytes_lower",
                "d_total_simulated_bytes_upper",
                "interval_width_bytes",
            ),
        )
        writer.writeheader()
        for case in report["cases"]:
            low = case["bounds"]["lower"]
            high = case["bounds"]["upper"]
            writer.writerow(
                {
                    "n": case["n"],
                    "t": case["t"],
                    "batch_size": case["batch_size"],
                    "depth": case["depth"],
                    "combined_private_ciphertext_bytes_per_receiver": case[
                        "payload_calibration"
                    ]["combined_private_ciphertext_bytes_per_receiver"],
                    "current_ap_bytes_per_handoff": low[
                        "per_handoff_current_ap_bytes"
                    ],
                    "simulated_ap_bytes_per_handoff_lower": low[
                        "per_handoff_simulated_ap_bytes"
                    ],
                    "simulated_ap_bytes_per_handoff_upper": high[
                        "per_handoff_simulated_ap_bytes"
                    ],
                    "reduction_fraction_lower": high["reduction_fraction"],
                    "reduction_fraction_upper": low["reduction_fraction"],
                    "d_total_simulated_bytes_lower": low[
                        "d_total_simulated_ap_bytes"
                    ],
                    "d_total_simulated_bytes_upper": high[
                        "d_total_simulated_ap_bytes"
                    ],
                    "interval_width_bytes": case[
                        "simulation_interval_width_bytes"
                    ],
                }
            )

    manifest_lines = []
    for path in (csv_path, json_path, markdown_path):
        manifest_lines.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        )
    (output_dir / "MANIFEST.sha256").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8"
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-root", type=Path, default=DEFAULT_LOCAL_ROOT)
    parser.add_argument("--n22-log-root", type=Path, default=DEFAULT_N22_LOG_ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    report = build_report(args.local_root, args.n22_log_root)
    write_outputs(report, args.output_dir)
    print(render_markdown(report), end="")
    print(f"Wrote auditable outputs to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
