"""Low-overhead local cryptographic timing for protocol proof operations."""

from time import perf_counter_ns


AGGTRANS_LEGACY_GENERATE_COMPONENTS = ("legacy_aggpub_prove",)
AGGTRANS_LEGACY_VERIFY_COMPONENTS = ("legacy_aggpub_verify",)
AGGTRANS_GENERATE_COMPONENTS = ("aggpub_prove",)
AGGTRANS_VERIFY_COMPONENTS = ("aggpub_verify",)
AGGTRANS_BACSS_GENERATE_COMPONENTS = ("commitment_opening_generation",)
AGGTRANS_BACSS_VERIFY_COMPONENTS = ("evaluation_proof_verify",)
AGGTRANS_NOAGG_GENERATE_COMPONENTS = (
    "commitment_opening_generation",
    "pedersen_commitment_preparation",
)
AGGTRANS_NOAGG_VERIFY_COMPONENTS = (
    "evaluation_proof_verify",
    "old_anchor_batch_verify",
    "fresh_zero_batch_verify",
)
BATCHMUL_GENERATE_COMPONENTS = (
    "multiplication_witness_preparation",
    "factor_proof",
    "output_commitment_preparation",
    "challenge_derivation",
    "output_zero_aggregation",
    "left_anchor_aggregation",
    "right_anchor_aggregation",
    "anchor_share_preparation",
    "pedersen_commitment_preparation",
)
BATCHMUL_VERIFY_COMPONENTS = (
    "factor_verify",
    "aggped_batch_verify",
)
BATCHMUL_BACSS_VERIFY_COMPONENTS = ("evaluation_proof_verify",)
BGW_GENERATE_COMPONENTS = ("degree_reduction_proof_generation",)
BGW_VERIFY_COMPONENTS = (
    "share_evaluation_verify",
    "hidden_evaluation_verify",
    "zero_evaluation_verify",
    "product_relation_verify",
)


def bgw_effective_batch_size(committee_size, configured_width):
    """Return the gate count preserved by the remainder-aware BGW input path.

    The BGW baseline distributes all ``2 * configured_width`` input sharings:
    the first remainder dealers receive one additional input, and the merge
    path keeps every dealer's full contribution.  The two equal operands
    therefore retain exactly ``configured_width`` multiplication gates for
    every committee size.
    """
    committee_size = int(committee_size)
    configured_width = int(configured_width)
    if committee_size <= 0 or configured_width <= 0:
        raise ValueError("BGW committee size and configured width must be positive")
    return configured_width


def aggtrans_generate_components(mode):
    if mode == "v2":
        return AGGTRANS_GENERATE_COMPONENTS
    if mode == "legacy":
        return AGGTRANS_LEGACY_GENERATE_COMPONENTS
    if mode == "shadow":
        return AGGTRANS_GENERATE_COMPONENTS + AGGTRANS_LEGACY_GENERATE_COMPONENTS
    raise ValueError(f"unsupported AggTrans metrics mode {mode!r}")


def aggtrans_verify_components(mode):
    if mode == "v2":
        return AGGTRANS_VERIFY_COMPONENTS
    if mode == "legacy":
        return AGGTRANS_LEGACY_VERIFY_COMPONENTS
    if mode == "shadow":
        return AGGTRANS_VERIFY_COMPONENTS
    raise ValueError(f"unsupported AggTrans metrics mode {mode!r}")


def _artifact(mpc_instance):
    recorder = getattr(mpc_instance, "metrics_recorder", None)
    return getattr(recorder, "communication_metrics", None)


def proof_metadata(
    mpc_instance,
    *,
    protocol,
    operation,
    dealer_local_id,
    receiver_local_id,
    batch_size,
    normalization_count=None,
    unit=None,
    source_layer=None,
    target_layer=None,
):
    # Legacy duplicate Hbacss classes have no MPC instance. They keep the
    # direct-call path and the placeholder metadata is never persisted.
    layer = int(getattr(mpc_instance, "layer_ID", -1))
    generating = operation.endswith("generate")
    if source_layer is None:
        source_layer = layer if generating else layer - 1
    if target_layer is None:
        target_layer = layer + 1 if generating else layer
    receiver_token = "none" if receiver_local_id is None else int(receiver_local_id)
    operation_id = (
        f"{protocol}:{target_layer}:dealer:{int(dealer_local_id)}:"
        f"receiver:{receiver_token}:{operation}"
    )
    metadata = {
        "protocol": protocol,
        "operation": operation,
        "operation_id": operation_id,
        "source_layer": source_layer,
        "target_layer": target_layer,
        "dealer_local_id": int(dealer_local_id),
        "receiver_local_id": (
            None if receiver_local_id is None else int(receiver_local_id)
        ),
        "batch_size": int(batch_size),
        "normalization_count": int(
            batch_size if normalization_count is None else normalization_count
        ),
    }
    if unit is not None:
        metadata["unit"] = str(unit)
    return metadata


def timed_call(mpc_instance, metadata, component, function, *args, success=None):
    """Time one synchronous local call; disabled metrics take the direct path."""
    artifact = _artifact(mpc_instance)
    if artifact is None or not artifact.enabled:
        return function(*args)
    started = perf_counter_ns()
    try:
        result = function(*args)
    except BaseException:
        elapsed_ns = perf_counter_ns() - started
        artifact.record_proof_component({
            **metadata, "component": component, "elapsed_ns": elapsed_ns,
            "success": False,
        })
        raise
    elapsed_ns = perf_counter_ns() - started
    call_success = True if success is None else bool(success(result))
    artifact.record_proof_component({
        **metadata, "component": component, "elapsed_ns": elapsed_ns,
        "success": call_success,
    })
    return result


def finalize_operation(mpc_instance, metadata, required_components, success):
    artifact = _artifact(mpc_instance)
    if artifact is None or not artifact.enabled:
        return
    artifact.finalize_proof_operation(metadata, required_components, success)
