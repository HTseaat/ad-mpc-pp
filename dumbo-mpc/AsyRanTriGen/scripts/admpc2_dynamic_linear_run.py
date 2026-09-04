from beaver.admpc_config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner
from beaver.admpc2_dynamic_linear import ADMPC_Multi_Layer_Control, ADMPC_Dynamic

# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod
import asyncio
import time
import logging
import uvloop
import numpy as np
import pickle
import json
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

CANONICAL_COMMUNICATION_PROFILE = "bls12-381-fr32-g1-48-v1"


def _communication_metrics_context(n, t, layers, my_id, my_send_id, total_cm):
    depth = layers - 2
    # The active Figure 8 implementation fixes circuit width at 100.  ``cm``
    # is not the Transfer input-vector length; runtime registration below reads
    # the actual proof vector and the analyzer checks it against this value.
    configured_width = int(os.environ.get("CIRCUIT_WIDTH", "100"))
    no_aggregation = os.environ.get("DISABLE_AGG_PROTO", "0") == "1"
    return {
        "implementation": "continuum",
        "experiment": "figure8",
        "protocol_variant": "aggtrans-noagg" if no_aggregation else "aggtrans",
        "run_id": os.environ.get(
            "PROTOCOL_OVERHEAD_RUN_ID", HbmpcConfig.extras.get("run_id", "local")
        ),
        "parameters": {
            "committee_size": int(n), "threshold": int(t),
            "total_layers": int(layers), "circuit_depth": int(depth),
            "total_cm": int(total_cm), "configured_width": configured_width,
            "expected_batch_size": configured_width, "expected_operations": int(depth),
            "expected_processes": int(n * layers), "proof_metrics_expected": True,
            "cryptographic_payload_encoding": "decimal-json",
            "canonical_communication_profile": CANONICAL_COMMUNICATION_PROFILE,
            "agg_kzg_mode": os.environ.get("AGG_KZG_V2", "1"),
        },
        "process": {
            "global_process_id": int(my_send_id), "local_party_id": int(my_id),
            "physical_layer": int(my_send_id / n),
        },
        "selection": {
            "included_tags": [f"TR{target}" for target in range(2, layers)],
            "excluded_tag_prefixes": [
                "A", "CE:", "committee_election", "RR_TR",
                "LOCAL_METRICS_BARRIER",
            ],
            "normalization_unit": "sharing",
        },
    }


async def _run(peers, n, t, my_id, start_time, layers, my_send_id, total_cm, pbk, pvk, pks, sk, srs, next_pks_acss=None):

    logging.info(f"my_send_id: {my_send_id}")
    async with ProcessProgramRunner(
        peers, n * layers, t, my_send_id, auth_config=HbmpcConfig.extras,
        metrics_context=_communication_metrics_context(
            n, t, layers, my_id, my_send_id, total_cm
        ),
    ) as runner:
        send, recv = runner.get_send_recv("")
        logging.debug(f"Starting ADMPC: {(my_id)}")
        logging.debug(f"Start time: {(start_time)}, diff {(start_time-int(time.time()))}")

        benchmark_logger = logging.LoggerAdapter(
           logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )
        # curve_params = (ZR, G1, multiexp, dotprod)
        layerID = int(my_send_id/n)
        with ADMPC_Dynamic(pks, sk, pbk, pvk, n, t, srs, my_id, send, recv, total_cm, layers, next_pks=next_pks_acss, layerID=layerID, metrics_recorder=runner.node_communicator) as admpc: 
            # while True:
            #     if time.time() > start_time:
            #         break
            #     time.sleep(0.1)
            
            # Wait until the configured start time, if any
            if start_time is not None:
                while time.time() < start_time:
                    await asyncio.sleep(0.1)
            begin_time = time.time()
            logging.info(f"ADMPC start time: {(begin_time)}")
            admpc_task = asyncio.create_task(admpc.run_admpc(begin_time))
            await admpc_task


            exec_time = time.time() - begin_time
            print(f"my_send_id: {my_send_id} exec_time: {exec_time}")
            if os.environ.get("PROTOCOL_OVERHEAD_METRICS", "0").lower() in {
                "1", "true", "yes", "on"
            }:
                checkpoint_path = (
                    runner.node_communicator.write_metrics_checkpoint()
                )
                logging.info(
                    "Protocol-overhead checkpoint written: %s",
                    checkpoint_path,
                )
                # A completed node must remain online while slower peers finish
                # MVBA.  This explicit barrier avoids relying on a guessed sleep
                # duration and is excluded from the measured protocol tags.
                barrier_send, barrier_recv = runner.get_send_recv(
                    "LOCAL_METRICS_BARRIER"
                )
                for process_id in range(n * layers):
                    barrier_send(process_id, "ready")
                ready = set()
                while len(ready) < n * layers:
                    sender, message = await barrier_recv()
                    if message == "ready":
                        ready.add(sender)
            print("Finished")
            # Give the monitor time to observe the marker before normal exit.
            await asyncio.sleep(float(os.environ.get("POST_EXEC_SLEEP_SECONDS", "5")))



        
        bytes_sent = runner.node_communicator.bytes_sent
        for k,v in runner.node_communicator.bytes_count.items():
            logging.info(f"[{my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logging.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")

if __name__ == "__main__":
    from beaver.admpc_config import HbmpcConfig
    logging.info("Running ADMPC ...")
    HbmpcConfig.load_config()

    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)

    from beaver.broadcast.crypto.boldyreva import TBLSPublicKey  # noqa:F401
    from beaver.broadcast.crypto.boldyreva import TBLSPrivateKey  # noqa:F401
    import base64

    pbk = pickle.loads(base64.b64decode(HbmpcConfig.extras["public_key"]))
    pvk = pickle.loads(base64.b64decode(HbmpcConfig.extras["private_key"]))

    pks = base64.b64decode(HbmpcConfig.extras["pks_acss"])
    sk = base64.b64decode(HbmpcConfig.extras["sk_acss"])
    serialized_srs = base64.b64decode(HbmpcConfig.extras["SRS"])
    deserialized_srs_kzg = json.loads(serialized_srs.decode('utf-8'))
    srs = {}
    srs['Pk'] = json.dumps(deserialized_srs_kzg['Pk']).encode('utf-8')
    srs['Vk'] = json.dumps(deserialized_srs_kzg['Vk']).encode('utf-8')

    # Parse next committee's ACSS public key for hand-off
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
                next_pks_acss
            )
        )
    finally:
        loop.close()
