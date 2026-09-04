from beaver.admpc_config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner
from beaver.admpc2_dynamic_bgw_aggtrans import ADMPC_Dynamic
from beaver.protocol_metrics import bgw_effective_batch_size

import asyncio
import base64
import json
import logging
import os
import pickle
import sys
import time

import uvloop


sys.path.insert(0, os.path.dirname(__file__))

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.NOTSET)

METRICS_TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_METRICS_BARRIER_TIMEOUT_SECONDS = 300.0
CANONICAL_COMMUNICATION_PROFILE = "bls12-381-fr32-g1-48-v1"


def _metrics_enabled():
    return (
        os.environ.get("PROTOCOL_OVERHEAD_METRICS", "0").lower()
        in METRICS_TRUE_VALUES
    )


def _metrics_barrier_timeout_seconds():
    raw_value = os.environ.get(
        "PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS",
        str(DEFAULT_METRICS_BARRIER_TIMEOUT_SECONDS),
    )
    try:
        timeout = float(raw_value)
    except ValueError as exc:
        raise ValueError(
            "PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS must be numeric"
        ) from exc
    if timeout <= 0:
        raise ValueError(
            "PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS must be positive"
        )
    return timeout


async def _wait_for_metrics_barrier(runner, total_processes):
    barrier_send, barrier_recv = runner.get_send_recv(
        "LOCAL_METRICS_BARRIER"
    )
    for process_id in range(total_processes):
        barrier_send(process_id, "ready")
    ready = set()
    while len(ready) < total_processes:
        sender, message = await barrier_recv()
        if message == "ready":
            ready.add(sender)
    return ready


def _communication_metrics_context(n, t, layers, my_id, my_send_id, total_cm):
    depth = layers - 2
    width = int(total_cm / depth) if depth > 0 else int(total_cm)
    effective_batch_size = bgw_effective_batch_size(n, width)
    return {
        "implementation": "continuum",
        "experiment": "figure9",
        "protocol_variant": "bgw-aggtrans",
        "run_id": HbmpcConfig.extras.get(
            "run_id", os.environ.get("PROTOCOL_OVERHEAD_RUN_ID", "local")
        ),
        "parameters": {
            "committee_size": int(n), "threshold": int(t),
            "total_layers": int(layers), "circuit_depth": int(depth),
            "total_cm": int(total_cm), "configured_width": int(width),
            "expected_batch_size": int(effective_batch_size),
            "expected_operations": int(depth),
            "expected_processes": int(n * layers),
            "proof_metrics_expected": True,
            "cryptographic_payload_encoding": "decimal-json",
            "canonical_communication_profile": CANONICAL_COMMUNICATION_PROFILE,
            "agg_kzg_mode": os.environ.get("AGG_KZG_V2", "1"),
            "bgw_unbatched_verify": (
                os.environ.get("BGW_UNBATCHED_VERIFY", "0") == "1"
            ),
        },
        "process": {
            "global_process_id": int(my_send_id),
            "local_party_id": int(my_id),
            "physical_layer": int(my_send_id / n),
        },
        "selection": {
            "included_tags": (
                [f"M_BGW_{layer}" for layer in range(1, depth + 1)]
                + [f"TR{layer + 1}" for layer in range(1, depth + 1)]
            ),
            "excluded_tag_prefixes": [
                "A", "RR_TR", "LOCAL_METRICS_BARRIER",
            ],
            "normalization_unit": "gate",
        },
    }


def _register_baseline_batches(
        recorder, n, layers, total_cm, physical_layer):
    depth = layers - 2
    width = int(total_cm / depth) if depth > 0 else int(total_cm)
    effective_batch_size = bgw_effective_batch_size(n, width)
    for computation_layer in range(1, depth + 1):
        operation_id = f"layer:{computation_layer}"
        if physical_layer == computation_layer:
            recorder.register_protocol_batch(
                protocol="bgw", tag=f"M_BGW_{computation_layer}",
                source_layer=computation_layer,
                target_layer=computation_layer,
                batch_size=effective_batch_size, role="participant",
                operation_id=operation_id, unit="gate",
            )
        tag = f"TR{computation_layer + 1}"
        if physical_layer == computation_layer:
            role = "source"
        elif physical_layer == computation_layer + 1:
            role = "destination"
        else:
            continue
        recorder.register_protocol_batch(
            protocol="aggtrans", tag=tag,
            source_layer=computation_layer,
            target_layer=computation_layer + 1,
            batch_size=effective_batch_size, role=role,
            operation_id=operation_id, unit="gate",
        )


async def _run(
    peers,
    n,
    t,
    my_id,
    start_time,
    layers,
    my_send_id,
    total_cm,
    pbk,
    pvk,
    pks,
    sk,
    srs,
    next_pks_acss=None,
):
    logging.info(f"my_send_id: {my_send_id}")
    async with ProcessProgramRunner(
        peers,
        n * layers,
        t,
        my_send_id,
        auth_config=HbmpcConfig.extras,
        metrics_context=_communication_metrics_context(
            n, t, layers, my_id, my_send_id, total_cm
        ),
    ) as runner:
        _register_baseline_batches(
            runner.node_communicator, n, layers, total_cm,
            int(my_send_id / n),
        )
        send, recv = runner.get_send_recv("")
        layerID = int(my_send_id / n)
        with ADMPC_Dynamic(
            pks,
            sk,
            pbk,
            pvk,
            n,
            t,
            srs,
            my_id,
            send,
            recv,
            total_cm,
            layers,
            next_pks=next_pks_acss,
            layerID=layerID,
            metrics_recorder=runner.node_communicator,
        ) as admpc:
            if start_time is not None:
                while time.time() < start_time:
                    await asyncio.sleep(0.1)
            begin_time = time.time()
            logging.info(f"BGW+AggTrans ADMPC start time: {begin_time}")
            admpc_task = asyncio.create_task(admpc.run_admpc(begin_time))
            await admpc_task

            exec_time = time.time() - begin_time
            print(f"my_send_id: {my_send_id} exec_time: {exec_time}")
            if _metrics_enabled():
                checkpoint_path = (
                    runner.node_communicator.write_metrics_checkpoint()
                )
                logging.info(
                    "Protocol-overhead checkpoint written: %s",
                    checkpoint_path,
                )
                barrier_timeout = _metrics_barrier_timeout_seconds()
                try:
                    await asyncio.wait_for(
                        _wait_for_metrics_barrier(runner, n * layers),
                        timeout=barrier_timeout,
                    )
                except asyncio.TimeoutError:
                    logging.warning(
                        "LOCAL_METRICS_BARRIER timed out after %.3fs; "
                        "the protocol-complete checkpoint remains usable",
                        barrier_timeout,
                    )
            # This is deliberately after exec_time and the protocol-complete
            # checkpoint.  It preserves normal n-t latency while keeping BGW
            # AVID responders alive long enough for slower honest peers.
            admpc.cleanup_bgw_responders()
            print("Finished")
            await asyncio.sleep(float(os.environ.get("POST_EXEC_SLEEP_SECONDS", "5")))

        bytes_sent = runner.node_communicator.bytes_sent
        for k, v in runner.node_communicator.bytes_count.items():
            pct = round((100 * v) / bytes_sent, 3) if bytes_sent else 0
            logging.info(f"[{my_id}] Bytes Sent: {k}:{v} which is {pct}%")
        logging.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")


if __name__ == "__main__":
    logging.info("Running BGW+AggTrans ADMPC ...")
    HbmpcConfig.load_config()

    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)

    from beaver.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
    from beaver.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401

    pbk = pickle.loads(base64.b64decode(HbmpcConfig.extras["public_key"]))
    pvk = pickle.loads(base64.b64decode(HbmpcConfig.extras["private_key"]))

    pks = base64.b64decode(HbmpcConfig.extras["pks_acss"])
    sk = base64.b64decode(HbmpcConfig.extras["sk_acss"])
    serialized_srs = base64.b64decode(HbmpcConfig.extras["SRS"])
    deserialized_srs_kzg = json.loads(serialized_srs.decode("utf-8"))
    srs = {
        "Pk": json.dumps(deserialized_srs_kzg["Pk"]).encode("utf-8"),
        "Vk": json.dumps(deserialized_srs_kzg["Vk"]).encode("utf-8"),
    }

    next_pk_b64 = HbmpcConfig.extras.get("next_pks_acss", "")
    if next_pk_b64:
        next_pks_acss = json.loads(base64.b64decode(next_pk_b64).decode("utf-8"))
    else:
        next_pks_acss = None

    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                HbmpcConfig.time,
                HbmpcConfig.layers,
                HbmpcConfig.my_send_id,
                HbmpcConfig.total_cm,
                pbk,
                pvk,
                pks,
                sk,
                srs,
                next_pks_acss,
            )
        )
    finally:
        loop.close()
