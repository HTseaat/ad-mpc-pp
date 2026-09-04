import asyncio
import json
import logging
import os
import time

import numpy as np
from pypairing import G1, ZR, blsmultiexp as multiexp, dotprod
import uvloop

from adkg.admpc_dynamic import ADMPC_Multi_Layer_Control
from adkg.config import HbmpcConfig
from adkg.admpc_dynamic_shuffle import (
    ADMPC_Dynamic_Shuffle,
    randbit_candidate_capacity,
    shuffle_triple_count,
)
from adkg.poly_commit_hybrid import PolyCommitHybrid
from adkg.shuffle_ipc import (
    ShuffleProcessProgramRunner,
    adjacent_peer_ids,
)


def get_avss_params(total_parties):
    g, h = G1.rand(b"g"), G1.rand(b"h")
    private_keys = [ZR.hash(str(index).encode()) for index in range(total_parties)]
    public_keys = [g ** private_key for private_key in private_keys]
    return g, h, public_keys, private_keys


def gen_vector(t, n):
    return np.array([[ZR(i + 1) ** j for j in range(n)] for i in range(n - t)]).tolist()


async def _run(peers, n, t, k, my_id, start_time, layers, my_send_id, total_cm):
    del total_cm
    shuffle_k = int(os.environ.get("SHUFFLE_K", "128"))
    shuffle_mode = os.environ.get("SHUFFLE_MODE", "iterated").strip().lower()
    ack_timeout = float(os.environ.get("SHUFFLE_ACK_TIMEOUT", "600"))
    ack_threshold = int(os.environ.get("SHUFFLE_ACK_THRESHOLD", str(n)))
    run_id = os.environ.get("ADMPC_SHUFFLE_RUN_ID", "admpc-shuffle-local")

    g, h, public_keys, private_keys = get_avss_params(n * layers)
    controller = ADMPC_Multi_Layer_Control(
        n=n,
        t=t,
        deg=k,
        layer_num=layers,
        total_cm=shuffle_triple_count(t, shuffle_k // 2),
        pks=public_keys,
    )
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    matrix = gen_vector(t, n)
    layer_id = my_send_id // n
    current_public_keys = controller.pks_all[layer_id]
    allowed_peers = adjacent_peer_ids(my_send_id, n, layers)

    async with ShuffleProcessProgramRunner(
        peers,
        n,
        t,
        my_send_id,
        allowed_peers,
        auth_config=HbmpcConfig.extras,
    ) as runner:
        send, recv = runner.get_send_recv("")
        delay = start_time - time.time()
        if delay > 0:
            await asyncio.sleep(delay)
        begin_time = time.time()
        protocol = ADMPC_Dynamic_Shuffle(
            current_public_keys,
            private_keys[my_send_id],
            g,
            h,
            n,
            t,
            k,
            my_id,
            send,
            recv,
            pc,
            (ZR, G1, multiexp, dotprod),
            matrix,
            shuffle_triple_count(t, shuffle_k // 2),
            layerID=layer_id,
            admpc_control_instance=controller,
            shuffle_k=shuffle_k,
            shuffle_mode=shuffle_mode,
            run_id=run_id,
            ack_timeout=ack_timeout,
            ack_threshold=ack_threshold,
        )
        try:
            result = await protocol.run_admpc(begin_time)
            finished_at = time.time()
        finally:
            protocol.kill()
            # Resource kill methods cancel their subscription tasks. Give the
            # loop a scheduling turn to deliver those cancellations before
            # the module-level uvloop is closed; this is post-protocol cleanup.
            await asyncio.sleep(0)
        elapsed = finished_at - begin_time
        marker = {
            "schema": "admpc-shuffle-finished-v2",
            "run_id": run_id,
            "global_id": my_send_id,
            "layer": layer_id,
            "local_party": my_id,
            "n": n,
            "t": t,
            "k": shuffle_k,
            "mode": shuffle_mode,
            "switch_layers": protocol.switch_layers,
            "physical_layers": protocol.physical_layers,
            "protocol_started_at": begin_time,
            "protocol_finished_at": finished_at,
            "elapsed": elapsed,
            "transport_topology": "adjacent",
            "allowed_peer_count": len(allowed_peers),
            "candidate_count": randbit_candidate_capacity(t, shuffle_k // 2),
            "result": result,
        }
        print("ADMPC_SHUFFLE_FINISHED " + json.dumps(marker, sort_keys=True))
        logging.info(
            "[%d] AD-MPC shuffle bytes sent: %d",
            my_send_id,
            runner.node_communicator.bytes_sent,
        )


if __name__ == "__main__":
    logging.info("Running AD-MPC Figure 12 shuffle ...")
    HbmpcConfig.load_config()
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
                HbmpcConfig.total_cm,
            )
        )
    finally:
        loop.close()
