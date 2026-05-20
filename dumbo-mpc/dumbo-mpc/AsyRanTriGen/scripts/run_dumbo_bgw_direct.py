from beaver.config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner

import asyncio
import base64
import json
import logging
import math
import os
import pickle
import sys
import time
from ctypes import CDLL, c_char_p, c_int

from beaver.bgw_multiplication_static import StaticBGWReduction
from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.hbacss import Hbacss1
from beaver.utils.misc import subscribe_recv, wrap_send
from optimizedhbmpc.elliptic_curve import Subgroup
from optimizedhbmpc.field import GF
from optimizedhbmpc.mpc import Mpc


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p
if hasattr(lib, "pySetN"):
    lib.pySetN.argtypes = [c_int]
    lib.pySetN.restype = None


class DumboBGWDirect:
    """Evaluate an all-multiplication circuit with Dumbo-MPC BGW directly."""

    def __init__(
        self,
        public_keys,
        private_key,
        pkbls,
        skbls,
        n,
        t,
        srs,
        my_id,
        send,
        recv,
        batchsize,
        layers,
        dumbo_mode="full",
    ):
        self.public_keys = public_keys
        self.private_key = private_key
        self.pkbls = pkbls
        self.skbls = skbls
        self.n = n
        self.t = t
        self.srs = srs
        self.my_id = my_id
        self.send = send
        self.recv = recv
        self.batchsize = int(batchsize)
        self.layers = int(layers)
        self.dumbo_mode = str(dumbo_mode or "full").strip().lower()
        if self.dumbo_mode not in ("full", "drop-epoch4", "drop_epoch4"):
            raise ValueError(
                f"Unknown dumbo mode: {dumbo_mode}. Expected one of: full, drop-epoch4"
            )
        self.acss_instances = []
        self.acss_tasks = []
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        if hasattr(lib, "pySetN"):
            lib.pySetN(self.n)

        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

    def _should_skip_layer(self, layer_id):
        return (
            self.dumbo_mode in ("drop-epoch4", "drop_epoch4")
            and layer_id == 3
            and self.my_id in (0, 1)
        )

    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
        except Exception:
            pass
        for task in self.acss_tasks:
            if task is not None:
                task.cancel()
        for acss in self.acss_instances:
            try:
                acss.kill()
            except Exception:
                logger.debug("[%d] BGW-direct ACSS cleanup raised", self.my_id, exc_info=True)

    async def _run_acss_acs(self, tag_prefix, values, mode, leader):
        acsstag = tag_prefix + "_ACSS"
        acsssend = self.get_send(acsstag)
        acssrecv = self.subscribe_recv(acsstag)

        coms = None
        if mode == "avss_with_proof":
            decoded = json.loads(values.decode("utf-8"))
            coms = json.dumps(decoded["commitment"]).encode("utf-8")

        acss = Hbacss1(
            self.public_keys,
            self.private_key,
            self.srs,
            self.n,
            self.t,
            self.my_id,
            acsssend,
            acssrecv,
            mode,
        )
        self.acss_instances.append(acss)
        acss_tasks = [None] * self.n
        for dealer_id in range(self.n):
            if dealer_id == self.my_id:
                acss_tasks[dealer_id] = asyncio.create_task(
                    acss.avss(0, coms=coms, values=values)
                )
            else:
                acss_tasks[dealer_id] = asyncio.create_task(
                    acss.avss(0, coms=coms, dealer_id=dealer_id)
                )
        self.acss_tasks.extend(acss_tasks)

        outputs = {}
        signal = asyncio.Event()

        async def collect_outputs():
            while True:
                try:
                    dealer, _, shares, commitments = await acss.output_queue.get()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("[%d] ACSS output handling failed for %s", self.my_id, tag_prefix)
                    continue
                outputs[dealer] = {"shares": shares, "commits": commitments}
                if len(outputs) >= self.n - self.t:
                    signal.set()
                if len(outputs) == self.n:
                    return

        collect_task = asyncio.create_task(collect_outputs())
        self.acss_tasks.append(collect_task)

        await signal.wait()
        signal.clear()
        proposal = list(outputs.keys())

        acstag = tag_prefix + "_ACS"
        acssend = self.get_send(acstag)
        acsrecv = self.subscribe_recv(acstag)
        logger.info(
            "[%d] %s proposal=%s",
            self.my_id,
            tag_prefix,
            sorted(proposal),
        )
        acs = OptimalCommonSet(
            acstag,
            self.my_id,
            self.n,
            self.t,
            leader,
            proposal,
            self.pkbls,
            self.skbls,
            acssend,
            acsrecv,
            outputs,
            signal,
        )
        try:
            common = sorted(list(await acs.handle_message()))
        finally:
            try:
                acs.subscribe_recv_task.cancel()
            except Exception:
                pass

        while any(dealer not in outputs for dealer in common):
            signal.clear()
            await signal.wait()

        logger.info("[%d] %s common=%s", self.my_id, tag_prefix, common)
        return common, outputs

    async def _share_initial_inputs(self, target_count):
        input_start = time.time()
        dealers_needed = self.n - self.t
        values_per_dealer = int(math.ceil(float(target_count) / dealers_needed))
        values = lib.pySampleSecret(values_per_dealer)
        common, outputs = await self._run_acss_acs(
            "DUMBO_BGW_INPUTS",
            values,
            "avss_without_proof",
            leader=0,
        )

        merged_shares = []
        merged_commits = []
        for dealer_id in common:
            merged_shares.extend(json.loads(outputs[dealer_id]["shares"].decode("utf-8")))
            merged_commits.extend(json.loads(outputs[dealer_id]["commits"].decode("utf-8")))

        if len(merged_shares) < target_count or len(merged_commits) < target_count:
            raise RuntimeError(
                f"Not enough initial inputs: shares={len(merged_shares)}, "
                f"commits={len(merged_commits)}, need={target_count}"
            )

        elapsed = time.time() - input_start
        logger.info(
            "[%d] dumbo_bgw_direct_input_time=%s, target=%s, values_per_dealer=%s, common=%s",
            self.my_id,
            elapsed,
            target_count,
            values_per_dealer,
            common,
        )
        return {
            "commitment": merged_commits[:target_count],
            "proof": merged_shares[:target_count],
        }

    @staticmethod
    def _slice_state(state, start, end):
        return {
            "commitment": state["commitment"][start:end],
            "proof": state["proof"][start:end],
        }

    async def _run_bgw_layer(self, layer_id, left_inputs, right_inputs, cm):
        bgwtag = "DUMBO_BGW_DIRECT_L" + str(layer_id)
        bgwsend = self.get_send(bgwtag)
        bgwrecv = self.subscribe_recv(bgwtag)
        bgw = StaticBGWReduction(
            self.public_keys,
            self.private_key,
            self.pkbls,
            self.skbls,
            self.n,
            self.t,
            self.srs,
            self.my_id,
            bgwsend,
            bgwrecv,
            cm,
        )
        try:
            return await bgw.run_multiply(left_inputs, right_inputs)
        finally:
            bgw.kill()

    async def _reconstruct_final_state(self, state):
        raw_proofs = state["proof"]
        claimed_values = [int(entry["ClaimedValue"]) for entry in raw_proofs]
        field = GF(Subgroup.BLS12_381)
        shares = [field(v) for v in claimed_values]
        tag_final = "DUMBO_BGW_DIRECT_FINAL_OPEN"
        send_fin = self.get_send(tag_final)
        recv_fin = self.subscribe_recv(tag_final)

        async def prog_final(ctx):
            return await ctx.ShareArray(shares, self.t).open()

        os.makedirs("sharedata_test", exist_ok=True)
        ctx_final = Mpc(
            "mpc:dumbo-bgw-direct-final",
            self.n,
            self.t,
            self.my_id,
            send_fin,
            recv_fin,
            prog_final,
            {},
        )
        return await ctx_final._run()

    async def run(self):
        if self.layers <= 0:
            raise ValueError("layers must be positive")
        cm = self.batchsize // self.layers
        if cm <= 0:
            raise ValueError(
                f"Invalid params: batchsize={self.batchsize}, layers={self.layers} -> cm={cm}"
            )
        if self.batchsize % self.layers != 0:
            logger.warning(
                "[%d] batchsize=%s is not divisible by layers=%s; evaluating %s gates",
                self.my_id,
                self.batchsize,
                self.layers,
                cm * self.layers,
            )

        total_start = time.time()
        logger.info(
            "[%d] Starting Dumbo-BGW direct evaluation: batchsize=%s, layers=%s, cm_per_layer=%s, mode=%s",
            self.my_id,
            self.batchsize,
            self.layers,
            cm,
            self.dumbo_mode,
        )

        state = await self._share_initial_inputs(2 * cm)
        for layer_id in range(self.layers):
            if self._should_skip_layer(layer_id):
                logger.warning(
                    "[%d] [layer %s] [DROP-EPOCH4] This BGW-direct node skips the 4th circuit layer "
                    "(0-indexed layer_id==3) for the Dumbo-MPC dropout baseline.",
                    self.my_id,
                    layer_id,
                )
                logger.warning(
                    "[%d] [layer %s] [DROP-EPOCH4] Other nodes may block waiting for BGW messages.",
                    self.my_id,
                    layer_id,
                )
                continue

            layer_start = time.time()
            if layer_id == 0:
                left_inputs = self._slice_state(state, 0, cm)
                right_inputs = self._slice_state(state, cm, 2 * cm)
            else:
                left_inputs = state
                right_inputs = state

            state = await self._run_bgw_layer(layer_id, left_inputs, right_inputs, cm)
            layer_elapsed = time.time() - layer_start
            logger.info(
                "[%d] [layer %s] dumbo_bgw_direct_layer_time=%s, gates=%s",
                self.my_id,
                layer_id,
                layer_elapsed,
                cm,
            )

        rec_start = time.time()
        final_values = await self._reconstruct_final_state(state)
        rec_elapsed = time.time() - rec_start
        total_elapsed = time.time() - total_start
        logger.info(
            "[%d] dumbo_bgw_direct_reconstruct_time=%s, outputs=%s",
            self.my_id,
            rec_elapsed,
            len(final_values),
        )
        logger.info(
            "[%d] Dumbo-BGW direct Finished! gates=%s, layers=%s, total_time=%s",
            self.my_id,
            cm * self.layers,
            self.layers,
            total_elapsed,
        )


async def _run(
    peers,
    pbk,
    pvk,
    n,
    t,
    my_id,
    batchsize,
    layers,
    pks,
    sk,
    srs,
    start_time,
    dumbo_mode,
):
    if hasattr(lib, "pySetN"):
        lib.pySetN(n)

    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        send, recv = runner.get_send_recv("")
        protocol = DumboBGWDirect(
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
            batchsize,
            layers,
            dumbo_mode,
        )
        try:
            while time.time() < start_time:
                await asyncio.sleep(0.1)
            begin_time = time.time()
            await protocol.run()
            exec_time = time.time() - begin_time
            print(f"my_id: {my_id} dumbo_bgw_direct_exec_time: {exec_time}", flush=True)
        finally:
            protocol.kill()


if __name__ == "__main__":
    HbmpcConfig.load_config()

    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()

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

    extras = HbmpcConfig.extras or {}
    batchsize = int(extras["k"])
    layers = int(extras.get("layers", 10))
    dumbo_mode = extras.get("dumbo_mode", "full")
    logger.info("Using dumbo BGW-direct mode: %s", dumbo_mode)

    try:
        loop.run_until_complete(
            _run(
                HbmpcConfig.peers,
                pbk,
                pvk,
                HbmpcConfig.N,
                HbmpcConfig.t,
                HbmpcConfig.my_id,
                batchsize,
                layers,
                pks,
                sk,
                srs,
                HbmpcConfig.time,
                dumbo_mode,
            )
        )
    finally:
        loop.close()

    time.sleep(1)
