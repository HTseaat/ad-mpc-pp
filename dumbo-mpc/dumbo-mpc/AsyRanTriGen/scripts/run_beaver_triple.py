from beaver.config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner, verify_all_connections
import asyncio
import time, sys
import logging
from ctypes import *
from importlib import import_module

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
if hasattr(lib, "pySetN"):
    lib.pySetN.argtypes = [c_int]
    lib.pySetN.restype = None

def _resolve_beaver_class(mode):
    normalized = str(mode or "full").strip().lower()
    if normalized == "full":
        module_name = "beaver.dumbo_mpc_dyn"
    elif normalized in ("drop-epoch4", "drop_epoch4"):
        module_name = "beaver.dumbo_mpc_dyn_dropout"
    else:
        raise ValueError(
            f"Unknown dumbo mode: {mode}. "
            "Expected one of: full, drop-epoch4"
        )
    return import_module(module_name).BEAVER


async def _run(peers, pbk, pvk, n, t, my_id, batchsize, layers, pks, sk, srs, start_time, beaver_cls):
    if hasattr(lib, "pySetN"):
        lib.pySetN(n)
    matrices = lib.VMmatrixGen(t)
    
    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("")
        with beaver_cls(pks, sk, pbk, pvk, n, t, srs, my_id, send, recv, matrices, batchsize, layers) as beaver:
            while True:
                if time.time() > start_time:
                    break
                time.sleep(0.1)
            beaver_task = asyncio.create_task(beaver.run_beaver(runner.node_communicator))
            await beaver_task
            beaver.kill()
            beaver_task.cancel()
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

    extras = HbmpcConfig.extras or {}
    batchsize = int(extras["k"])
    layers = int(extras.get("layers", 10))
    dumbo_mode = extras.get("dumbo_mode", "full")
    beaver_cls = _resolve_beaver_class(dumbo_mode)
    logging.info(f"Using dumbo mode: {dumbo_mode} ({beaver_cls.__module__})")

    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                pbk,
                pvk,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                # HbmpcConfig.extras["k"],
                batchsize,
                layers,
                pks, 
                sk,
                srs,
                HbmpcConfig.time,
                beaver_cls,
            )
        )
    finally:
        loop.close()
     
    time.sleep(1)
