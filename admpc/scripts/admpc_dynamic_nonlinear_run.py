from adkg.config import HbmpcConfig
from adkg.ipc import ProcessProgramRunner
from adkg.admpc_dynamic_nonlinear import ADMPC_Multi_Layer_Control, ADMPC_Dynamic
from adkg.poly_commit_hybrid import PolyCommitHybrid
from pypairing import ZR, G1, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod
import asyncio
import time
import logging
import uvloop
import numpy as np
import os

logger = logging.getLogger("benchmark_logger")
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
logger.setLevel(logging.NOTSET)

CANONICAL_COMMUNICATION_PROFILE = "bls12-381-fr32-g1-48-v1"


def _communication_metrics_context(n, t, layers, my_id, my_send_id, total_cm):
    depth = layers - 2
    width = int(total_cm / depth) if depth > 0 else int(total_cm)
    per_item = os.environ.get("ADTRANS_ALG4_PER_ITEM", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }
    return {
        "implementation": "admpc",
        "experiment": "figure9",
        "protocol_variant": "admpc-nonlinear",
        "run_id": (HbmpcConfig.extras or {}).get("run_id", os.environ.get("PROTOCOL_OVERHEAD_RUN_ID", "local")),
        "parameters": {
            "committee_size": int(n), "threshold": int(t),
            "total_layers": int(layers), "circuit_depth": int(depth),
            "total_cm": int(total_cm), "configured_width": int(width),
            "expected_batch_size": int(width), "expected_operations": int(depth),
            "expected_processes": int(n * layers), "proof_metrics_expected": True,
            "cryptographic_payload_encoding": CANONICAL_COMMUNICATION_PROFILE,
            "adtrans_alg4_mode": (
                "per-item-line204" if per_item else "aggregate"
            ),
            "evaluation_verifier_mode": "legacy-inner-proof-only",
        },
        "process": {
            "global_process_id": int(my_send_id), "local_party_id": int(my_id),
            "physical_layer": int(my_send_id / n),
        },
        "selection": {
            "included_tags": ([f"GR{target}" for target in range(1, depth + 1)] +
                              [f"AP{target}" for target in range(1, depth + 1)] +
                              [f"TR{target}" for target in range(2, layers)] + ["RR"]),
            "excluded_tag_prefixes": ["A", "LOCAL_METRICS_BARRIER"],
            "tag_layer_ranges": {"RR": [1, depth]},
            "normalization_unit": "gate",
        },
    }


def _register_baseline_batches(recorder, layers, total_cm, physical_layer):
    depth = layers - 2
    width = int(total_cm / depth) if depth > 0 else int(total_cm)
    for computation_layer in range(1, depth + 1):
        operation_id = f"layer:{computation_layer}"
        descriptors = [
            ("randgen", f"GR{computation_layer}", computation_layer - 1, computation_layer),
            ("adprep", f"AP{computation_layer}", computation_layer - 1, computation_layer),
            ("adtrans", f"TR{computation_layer + 1}", computation_layer, computation_layer + 1),
        ]
        for protocol, tag, source_layer, target_layer in descriptors:
            if physical_layer == source_layer:
                role = "source"
            elif physical_layer == target_layer:
                role = "destination"
            else:
                continue
            recorder.register_protocol_batch(
                protocol=protocol, tag=tag, source_layer=source_layer,
                target_layer=target_layer, batch_size=width, role=role,
                operation_id=operation_id, unit="gate",
            )
        if physical_layer == computation_layer:
            recorder.register_protocol_batch(
                protocol="exec", tag="RR", source_layer=computation_layer,
                target_layer=computation_layer, batch_size=width,
                role="participant", operation_id=operation_id, unit="gate",
            )

def get_avss_params(n):
    g, h = G1.rand(b'g'), G1.rand(b'h')
    public_keys, private_keys = [None] * n, [None] * n
    for i in range(n):
        # private_keys[i] = ZR.random()
        private_keys[i] = ZR.hash(str(i).encode())
        public_keys[i] = pow(g, private_keys[i])
    return g, h, public_keys, private_keys


def gen_vector(t, n, ZR):

    vm = np.array([[ZR(i+1)**j for j in range(n)] for i in range(n-t)])

    return (vm.tolist())

async def _run(peers, n, t, k, my_id, start_time, layers, my_send_id, total_cm):
    g, h, pks, sks = get_avss_params(n*layers)
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    deg = k
    mat = gen_vector(t, n, ZR)
    # 注意这里，在每个委员会中 servers 的编号都是从 0 开始的，因此在生成 send 和 recv 对的时候，要注意转换

    print(f"my_send_id: {my_send_id}")
    async with ProcessProgramRunner(
        peers, n*layers, t, my_send_id,
        metrics_context=_communication_metrics_context(
            n, t, layers, my_id, my_send_id, total_cm
        ),
    ) as runner:
        _register_baseline_batches(
            runner.node_communicator, layers, total_cm, int(my_send_id / n)
        )
        send, recv = runner.get_send_recv("")
        logging.debug(f"Starting ADMPC: {(my_id)}")
        logging.debug(f"Start time: {(start_time)}, diff {(start_time-int(time.time()))}")

        benchmark_logger = logging.LoggerAdapter(
           logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )
        curve_params = (ZR, G1, multiexp, dotprod)
        layerID = int(my_send_id/n)
        with ADMPC_Dynamic(pks, sks[my_send_id], g, h, n, t, deg, my_id, send, recv, pc, curve_params, mat, total_cm, layerID=layerID, metrics_recorder=runner.node_communicator) as admpc: 
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            begin_time = time.time()
            logging.info(f"ADMPC start time: {(begin_time)}")
            admpc_task = asyncio.create_task(admpc.run_admpc(begin_time))
            await admpc_task
            # admpc.kill()
            # admpc_task.cancel()
            exec_time = time.time() - begin_time
            print(f"my_send_id: {my_send_id} exec_time: {exec_time}")
            if os.environ.get("PROTOCOL_OVERHEAD_METRICS", "0").lower() in {
                "1", "true", "yes", "on"
            }:
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
            await asyncio.sleep(float(os.environ.get("POST_EXEC_SLEEP_SECONDS", "50")))



        
        bytes_sent = runner.node_communicator.bytes_sent
        for k,v in runner.node_communicator.bytes_count.items():
            logging.info(f"[{my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logging.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")

if __name__ == "__main__":
    from adkg.config import HbmpcConfig
    logging.info("Running ADMPC ...")
    HbmpcConfig.load_config()

    # admpc_controller = ADMPC_Multi_Layer_Control(HbmpcConfig.N, HbmpcConfig.t, HbmpcConfig.k, HbmpcConfig.layers)

    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.k,
                HbmpcConfig.my_id,
                HbmpcConfig.time,
                HbmpcConfig.layers, 
                HbmpcConfig.my_send_id,
                HbmpcConfig.total_cm
            )
        )
    finally:
        loop.close()
