from beaver.config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner, verify_all_connections
from beaver.beaver_triple import BEAVER
from beaver.transfer import DynamicTransfer
import asyncio
import time, sys
import logging
from ctypes import *
import sys

# Configure root logger for console output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

import json
import cProfile, pstats, io
# import uvloop

lib = CDLL("./kzg_ped_out.so")

import pickle
import os

lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p

lib.VMmatrixGen.argtypes = [c_int]
lib.VMmatrixGen.restype = c_char_p

async def _run(peers, pbk, pvk, n, t, my_id, batchsize, pks, sk, srs, start_time):
    
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        # -------------------------------------------------------------
        # Load pre‑generated commitments, shares and evaluation proofs
        # for the current node from init_inputs/node{my_id}.json
        # -------------------------------------------------------------
        init_path = os.path.join(
            os.path.dirname(__file__), "..", "init_inputs", f"node{my_id}.json"
        )
        # Fallback to relative path if script is executed from project root
        if not os.path.exists(init_path):
            init_path = f"init_inputs/node{my_id}.json"

        with open(init_path, "r") as f_init:
            init_comandproofs = json.load(f_init)

        send, recv = runner.get_send_recv("")
        with DynamicTransfer(
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
            batchsize,             # B secrets
            init_comandproofs,           # KZG commitments C_k^ℓ, local secret shares s_k^ℓ, evaluation proofs w_k^ℓ
        ) as transfer:
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            transfer_task = asyncio.create_task(transfer.run_transfer(runner.node_communicator))
            await transfer_task
            transfer.kill()
            transfer_task.cancel()
        # bytes_sent = runner.node_communicator.bytes_sent
        # for k,v in runner.node_communicator.bytes_count.items():
        #     print(f"[{my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        # print(f"[{my_id}] Total bytes sent out aa: {bytes_sent}")


if __name__ == "__main__":
    from beaver.config import HbmpcConfig
    HbmpcConfig.load_config()
    
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    
    # loop = uvloop.new_event_loop()
    # asyncio.set_event_loop(loop)
    
    #HbmpcConfig = HbmpcConfig()
    
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
    # loop.run_until_complete(
    #     verify_all_connections(HbmpcConfig.peers, HbmpcConfig.N, HbmpcConfig.my_id)
    #     )
    # print("verification of connection are completed!")

    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                pbk,
                pvk,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                HbmpcConfig.extras["k"],
                pks, 
                sk,
                srs,
                HbmpcConfig.time
            )
        )
    finally:
        loop.close()
     
    time.sleep(1)
