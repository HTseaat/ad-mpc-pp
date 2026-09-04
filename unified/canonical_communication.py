#!/usr/bin/env python3
"""Shared canonical accounting rules for the Figure 8/9 communication runs.

The protocol run determines which remote messages are sent and how often.
This module only normalizes cryptographic payload sizes so that AD-MPC's
fixed-width binary representation and Continuum's decimal JSON representation
can be compared under one encoding profile.
"""

from collections.abc import Mapping


PROFILE = "bls12-381-fr32-g1-48-v1"
FIELD_BYTES = 32
G1_BYTES = 48
SYMMETRIC_CIPHERTEXT_OVERHEAD = 46
AGGTRANS_PROOF_BYTES = 256
PRODUCT_PROOF_BYTES = 3 * G1_BYTES + 5 * FIELD_BYTES


class CanonicalCommunicationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CanonicalCommunicationError(message)


def stripe_bytes(payload_bytes, code_k):
    """Return the encoded stripe size used by the repository RBC/AVID code."""
    payload_bytes = int(payload_bytes)
    code_k = int(code_k)
    require(payload_bytes >= 0, "payload_bytes must be non-negative")
    require(code_k > 0, "code_k must be positive")
    # reliablebroadcast.encode adds a full padding byte/block when exact.
    return payload_bytes // code_k + 1


def computation_layer_result(
    canonical_bytes,
    *,
    batch_size,
    unit,
    circuit_depth,
    components=None,
):
    """Build the common result shape used by both figures.

    Figure 8 and Figure 9 use homogeneous circuits, so the measured local
    execution contains one representative computation layer.  The primary
    value is therefore communication per computation layer.  The depth-scaled
    value is retained as a derived convenience and never includes input
    distribution or final output reconstruction.
    """
    canonical_bytes = int(canonical_bytes)
    batch_size = int(batch_size)
    circuit_depth = int(circuit_depth)
    require(canonical_bytes >= 0, "canonical_bytes must be non-negative")
    require(batch_size > 0, "batch_size must be positive")
    require(circuit_depth > 0, "circuit_depth must be positive")
    require(unit in {"sharing", "gate"}, "unit must be sharing or gate")
    normalized_components = {
        str(name): int(value) for name, value in (components or {}).items()
    }
    require(
        not normalized_components
        or sum(normalized_components.values()) == canonical_bytes,
        "canonical components do not sum to the layer total",
    )
    return {
        "components_per_computation_layer": normalized_components,
        "canonical_bytes_per_computation_layer": canonical_bytes,
        f"canonical_bytes_per_{unit}": canonical_bytes / batch_size,
        "computation_layer_count": circuit_depth,
        "canonical_all_computation_layers_bytes": (
            canonical_bytes * circuit_depth
        ),
        "canonical_all_computation_layers_decimal_mb": (
            canonical_bytes * circuit_depth / 1_000_000
        ),
    }


def canonical_admpc_binary_result(
    summary,
    *,
    expected_components,
    batch_size,
    unit,
    circuit_depth,
):
    """Normalize an AD-MPC integrated run without synthetic protocol phases.

    AD-MPC serializes Fr/G1 protocol objects with fixed-width binary helpers.
    Consequently its measured selected-tag total is already expressed under
    this profile.  This function validates that declaration and, critically,
    includes only components that were executed by the integrated driver.
    """
    parameters = summary.get("parameters", {})
    require(
        parameters.get("cryptographic_payload_encoding") == PROFILE,
        "AD-MPC artifact is missing the canonical binary encoding profile; "
        "rerun it with the current Figure 8/9 runner",
    )
    components = summary.get("component_bytes")
    require(isinstance(components, Mapping), "missing AD-MPC component_bytes")
    expected = set(expected_components)
    observed = set(components)
    require(
        observed == expected,
        "AD-MPC component mismatch: expected {}, got {}".format(
            sorted(expected), sorted(observed)
        ),
    )
    normalized = {name: int(components[name]) for name in sorted(expected)}
    total = int(summary["system_total_payload_bytes"])
    require(sum(normalized.values()) == total, "AD-MPC components do not sum")
    return computation_layer_result(
        total,
        batch_size=batch_size,
        unit=unit,
        circuit_depth=circuit_depth,
        components=normalized,
    )


def profile_metadata():
    return {
        "profile": PROFILE,
        "field_bytes": FIELD_BYTES,
        "g1_bytes": G1_BYTES,
        "symmetric_ciphertext_overhead_bytes": (
            SYMMETRIC_CIPHERTEXT_OVERHEAD
        ),
        "aggtrans_common_proof_bytes": AGGTRANS_PROOF_BYTES,
        "bgw_product_proof_bytes": PRODUCT_PROOF_BYTES,
        "message_multiplicity": "measured sender-side remote messages",
        "transport_envelopes": (
            "measured application-level protocol/control envelopes; TCP, ZMTP, "
            "CURVE framing and retransmission are excluded"
        ),
    }
