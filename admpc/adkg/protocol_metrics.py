"""Local cryptographic-computation metrics for the AD-MPC baseline.

Only commitment, proof-generation, and proof-verification calls belong here.
Network/MVBA waiting, serialization, encryption, and protocol wall time are
deliberately outside this metric.
"""

from time import perf_counter_ns


ACSS_GENERATE_COMPONENTS = (
    "commitment_generation",
    "evaluation_proof_generation",
)
ACSS_VERIFY_COMPONENTS = ("evaluation_proof_verify",)
BUNDLE_GENERATE_COMPONENTS = ACSS_GENERATE_COMPONENTS + (
    "consistency_proof_generation",
)
BUNDLE_VERIFY_COMPONENTS = (
    "consistency_proof_verify",
    "evaluation_proof_verify",
)
TRANS_GENERATE_COMPONENTS = (
    "consistency_proof_generation",
    "transfer_commitment_generation",
    "evaluation_proof_generation",
)
TRANS_VERIFY_COMPONENTS = (
    "commitment_aggregation",
    "evaluation_proof_verify",
    "consistency_proof_verify",
)


def _artifact(acss):
    mpc = getattr(acss, "mpc_instance", None)
    recorder = getattr(mpc, "metrics_recorder", None)
    return getattr(recorder, "communication_metrics", None)


def proof_metadata(acss, *, direction, dealer_local_id, receiver_local_id,
                   batch_size):
    protocol = getattr(acss, "metrics_protocol", None)
    artifact = _artifact(acss)
    if protocol is None or artifact is None or not artifact.enabled:
        return None
    mpc = acss.mpc_instance
    layer = int(getattr(mpc, "layer_ID", -1))
    generating = direction == "generate"
    source_layer = layer if generating else layer - 1
    target_layer = layer + 1 if generating else layer
    operation = f"{protocol}_{direction}"
    receiver_token = (
        "none" if receiver_local_id is None else int(receiver_local_id)
    )
    normalization_count = int(
        getattr(mpc, "metrics_normalization_count", batch_size)
    )
    unit = artifact.context.get("selection", {}).get(
        "normalization_unit", "gate"
    )
    operation_id = (
        f"{protocol}:{target_layer}:dealer:{int(dealer_local_id)}:"
        f"receiver:{receiver_token}:{operation}"
    )
    return {
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
        "normalization_count": normalization_count,
        "unit": unit,
    }


def timed_call(acss, metadata, component, function, *args, success=None):
    artifact = _artifact(acss)
    if metadata is None or artifact is None or not artifact.enabled:
        return function(*args)
    started = perf_counter_ns()
    try:
        result = function(*args)
    except BaseException:
        artifact.record_proof_component({
            **metadata,
            "component": component,
            "elapsed_ns": perf_counter_ns() - started,
            "success": False,
        })
        raise
    call_success = True if success is None else bool(success(result))
    artifact.record_proof_component({
        **metadata,
        "component": component,
        "elapsed_ns": perf_counter_ns() - started,
        "success": call_success,
    })
    return result


def finalize_operation(acss, metadata, required_components, success):
    artifact = _artifact(acss)
    if metadata is None or artifact is None or not artifact.enabled:
        return
    artifact.finalize_proof_operation(metadata, required_components, success)
