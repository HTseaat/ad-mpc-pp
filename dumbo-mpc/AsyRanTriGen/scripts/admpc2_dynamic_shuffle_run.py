from beaver.admpc_config import HbmpcConfig
from beaver.shuffle_ipc import ShuffleProcessProgramRunner, adjacent_peer_ids
from beaver.admpc2_dynamic_shuffle import ADMPC_Dynamic

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
    allowed_peer_ids = adjacent_peer_ids(my_send_id, n, layers)
    async with ShuffleProcessProgramRunner(
        peers,
        n * layers,
        t,
        my_send_id,
        allowed_peer_ids,
        auth_config=HbmpcConfig.extras,
    ) as runner:
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
        ) as admpc:
            if start_time is not None:
                while time.time() < start_time:
                    await asyncio.sleep(0.1)
            begin_time = time.time()
            logging.info(f"Shuffle ADMPC start time: {begin_time}")
            admpc_task = asyncio.create_task(admpc.run_admpc(begin_time))
            await admpc_task

            exec_time = time.time() - begin_time
            print(f"my_send_id: {my_send_id} exec_time: {exec_time}", flush=True)
            logging.info("Shuffle Finished!")
            await asyncio.sleep(5)

        bytes_sent = runner.node_communicator.bytes_sent
        for k, v in runner.node_communicator.bytes_count.items():
            pct = round((100 * v) / bytes_sent, 3) if bytes_sent else 0
            logging.info(f"[{my_id}] Bytes Sent: {k}:{v} which is {pct}%")
        logging.info(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")


if __name__ == "__main__":
    logging.info("Running Shuffle ADMPC ...")
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
