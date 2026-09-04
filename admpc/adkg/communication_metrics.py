"""Auditable communication-metrics artifacts for protocol experiments.

The transport owns byte accounting.  This helper only validates experiment
metadata, records public batch descriptors, and atomically writes the final
post-drain snapshot.  It deliberately never receives protocol payloads.
"""

import json
import os
import re
import tempfile
import threading
from pathlib import Path


METRICS_ENV = "PROTOCOL_OVERHEAD_METRICS"
OUTPUT_DIR_ENV = "PROTOCOL_OVERHEAD_OUTPUT_DIR"
SCHEMA = "protocol-communication-v1"


def _enabled(value):
    if value is None:
        value = os.environ.get(METRICS_ENV, "0")
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._") or "run"


class CommunicationMetricsArtifact:
    """Collect non-secret metadata and write one artifact per logical process."""

    REQUIRED_CONTEXT = {
        "implementation",
        "experiment",
        "protocol_variant",
        "run_id",
        "parameters",
        "process",
        "selection",
    }

    def __init__(self, context=None, enabled=None, output_dir=None):
        self.enabled = _enabled(enabled)
        self.context = dict(context or {})
        self.output_dir = output_dir or os.environ.get(OUTPUT_DIR_ENV)
        self._batches = []
        self._batch_keys = set()
        self._proof_metrics = []
        self._proof_components = {}
        self._proof_quorums = []
        self._proof_quorum_keys = set()
        self._proof_lock = threading.Lock()
        self.output_path = None
        if self.enabled:
            missing = sorted(self.REQUIRED_CONTEXT - set(self.context))
            if missing:
                raise ValueError(
                    "communication metrics context is missing: " + ", ".join(missing)
                )
            if not self.output_dir:
                raise ValueError(
                    f"{OUTPUT_DIR_ENV} is required when {METRICS_ENV} is enabled"
                )

    def register_batch(self, **entry):
        required = {
            "protocol",
            "tag",
            "source_layer",
            "target_layer",
            "batch_size",
            "role",
            "operation_id",
            "unit",
        }
        missing = sorted(required - set(entry))
        if missing:
            raise ValueError("batch metadata is missing: " + ", ".join(missing))
        normalized = dict(entry)
        normalized["source_layer"] = int(normalized["source_layer"])
        normalized["target_layer"] = int(normalized["target_layer"])
        normalized["batch_size"] = int(normalized["batch_size"])
        if normalized["batch_size"] <= 0:
            raise ValueError("batch_size must be positive")
        key = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        if key not in self._batch_keys:
            self._batch_keys.add(key)
            self._batches.append(normalized)

    def write(self, communication, transport, completed, artifact_state="final"):
        if not self.enabled:
            return None
        process = self.context["process"]
        global_id = int(process["global_process_id"])
        with self._proof_lock:
            proof_metrics = list(self._proof_metrics)
            proof_quorums = list(self._proof_quorums)
        document = {
            "schema": SCHEMA,
            **self.context,
            "completed": bool(completed),
            "artifact_state": str(artifact_state),
            "transport": dict(transport),
            "communication": communication,
            "protocol_batches": sorted(
                self._batches,
                key=lambda item: (
                    item["operation_id"], item["role"], item["tag"]
                ),
            ),
            "proof_metrics": sorted(
                proof_metrics,
                key=lambda item: (
                    item["operation_id"], item["operation"],
                    item["component"] == "total", item["component"],
                ),
            ),
            "proof_quorums": sorted(
                proof_quorums,
                key=lambda item: (
                    item["protocol"], item["target_layer"],
                    item["receiver_local_id"],
                ),
            ),
        }
        output_dir = Path(self.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = "communication-{}-{:05d}.json".format(
            _safe_name(self.context["implementation"]), global_id
        )
        destination = output_dir / filename
        fd, temporary = tempfile.mkstemp(
            prefix=filename + ".", suffix=".tmp", dir=str(output_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        self.output_path = str(destination)
        return self.output_path

    def record_proof_component(self, entry):
        """Record one local crypto call; safe for executor verification threads."""
        if not self.enabled:
            return
        required = {
            "protocol", "operation", "operation_id", "component",
            "source_layer", "target_layer", "dealer_local_id",
            "receiver_local_id", "batch_size", "normalization_count",
            "elapsed_ns", "success",
        }
        missing = sorted(required - set(entry))
        if missing:
            raise ValueError("proof metric is missing: " + ", ".join(missing))
        normalized = dict(entry)
        for field in (
            "source_layer", "target_layer", "dealer_local_id", "batch_size",
            "normalization_count", "elapsed_ns",
        ):
            normalized[field] = int(normalized[field])
        if normalized["receiver_local_id"] is not None:
            normalized["receiver_local_id"] = int(normalized["receiver_local_id"])
        normalized["success"] = bool(normalized["success"])
        if (
            normalized["batch_size"] <= 0
            or normalized["normalization_count"] <= 0
            or normalized["elapsed_ns"] < 0
        ):
            raise ValueError("proof metric batch/normalization/elapsed value is invalid")
        key = (
            normalized["operation_id"], normalized["operation"],
            normalized["component"],
        )
        with self._proof_lock:
            if key in self._proof_components:
                raise ValueError("duplicate proof metric component: {}".format(key))
            self._proof_components[key] = normalized
            self._proof_metrics.append(normalized)

    def record_proof_quorum(self, entry):
        """Persist the frozen n-t dealer set used for paper computation.

        Raw proof metrics retain every completed background verification.  The
        analyzer uses this public control-flow marker to select only the
        dealer verifications needed to advance the protocol.
        """
        if not self.enabled:
            return
        required = {
            "protocol", "target_layer", "receiver_local_id", "dealer_ids",
            "required_count",
        }
        missing = sorted(required - set(entry))
        if missing:
            raise ValueError(
                "proof quorum is missing: " + ", ".join(missing)
            )
        normalized = dict(entry)
        normalized["target_layer"] = int(normalized["target_layer"])
        normalized["receiver_local_id"] = int(
            normalized["receiver_local_id"]
        )
        normalized["required_count"] = int(normalized["required_count"])
        normalized["dealer_ids"] = sorted(
            int(dealer_id) for dealer_id in normalized["dealer_ids"]
        )
        if normalized["required_count"] <= 0:
            raise ValueError("proof quorum required_count must be positive")
        if (
            len(normalized["dealer_ids"]) != normalized["required_count"]
            or len(set(normalized["dealer_ids"]))
            != normalized["required_count"]
            or any(dealer_id < 0 for dealer_id in normalized["dealer_ids"])
        ):
            raise ValueError(
                "proof quorum must contain exactly required_count unique "
                "non-negative dealer IDs"
            )
        key = (
            normalized["protocol"], normalized["target_layer"],
            normalized["receiver_local_id"],
        )
        with self._proof_lock:
            if key in self._proof_quorum_keys:
                raise ValueError("duplicate proof quorum: {}".format(key))
            self._proof_quorum_keys.add(key)
            self._proof_quorums.append(normalized)

    def finalize_proof_operation(self, metadata, required_components, success):
        """Emit a total defined exactly as the sum of named crypto calls."""
        if not self.enabled:
            return
        operation_id = metadata["operation_id"]
        operation = metadata["operation"]
        with self._proof_lock:
            components = []
            for component in required_components:
                key = (operation_id, operation, component)
                if key not in self._proof_components:
                    raise ValueError(
                        f"cannot finalize {operation_id}: missing component {component}"
                    )
                components.append(self._proof_components[key])
        total = dict(metadata)
        total.update({
            "component": "total",
            "elapsed_ns": sum(item["elapsed_ns"] for item in components),
            "success": bool(success),
            "included_components": list(required_components),
        })
        self.record_proof_component(total)
