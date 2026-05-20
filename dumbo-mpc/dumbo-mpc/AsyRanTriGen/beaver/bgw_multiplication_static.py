import asyncio
import json
import logging
import time
from ctypes import CDLL, c_char_p, c_int

from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.hbacss import Hbacss1
from beaver.utils.misc import subscribe_recv, wrap_send


logger = logging.getLogger(__name__)

lib = CDLL("./kzg_ped_out.so")

lib.pyInterpolateShareswithTransfer.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyInterpolateShareswithTransfer.restype = c_char_p

if hasattr(lib, "pySetN"):
    lib.pySetN.argtypes = [c_int]
    lib.pySetN.restype = None


class StaticBGWReductionMsg:
    ACSS = "STATIC_BGW_ACSS"
    ACS = "STATIC_BGW_ACS"


class StaticBGWReduction:
    """Dumbo-MPC BGW degree reduction inside one static committee."""

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
    ):
        self.public_keys = public_keys
        self.private_key = private_key
        self.pkbls = pkbls
        self.skbls = skbls
        self.n = n
        self.t = t
        self.srs = srs
        self.my_id = my_id
        self.batchsize = batchsize
        self.acss_tasks = []
        self.acss_task = None
        self.acss = None

        if hasattr(lib, "pySetN"):
            lib.pySetN(self.n)

        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        def _send(tag):
            return wrap_send(tag, send)

        self.get_send = _send

    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
        except Exception:
            pass
        for task in self.acss_tasks:
            if task is not None:
                task.cancel()
        if self.acss is not None:
            try:
                self.acss.kill()
            except Exception:
                logger.debug("[%d] Static BGW ACSS cleanup raised", self.my_id, exc_info=True)
        if self.acss_task is not None:
            self.acss_task.cancel()

    async def acss_step(self, outputs, values, acss_signal):
        acsssend = self.get_send(StaticBGWReductionMsg.ACSS)
        acssrecv = self.subscribe_recv(StaticBGWReductionMsg.ACSS)

        deser_values = json.loads(values.decode("utf-8"))
        com_ab = json.dumps(deser_values["commitment"]).encode("utf-8")

        self.acss = Hbacss1(
            self.public_keys,
            self.private_key,
            self.srs,
            self.n,
            self.t,
            self.my_id,
            acsssend,
            acssrecv,
            "avss_with_proof",
        )
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n):
            if dealer_id == self.my_id:
                self.acss_tasks[dealer_id] = asyncio.create_task(
                    self.acss.avss(0, coms=com_ab, values=values)
                )
            else:
                self.acss_tasks[dealer_id] = asyncio.create_task(
                    self.acss.avss(0, coms=com_ab, dealer_id=dealer_id)
                )

        while True:
            try:
                dealer, _, shares, commitments = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("[%d] Static BGW ACSS output handling failed", self.my_id)
                continue

            outputs[dealer] = {"shares": shares, "commits": commitments}
            if len(outputs) >= self.n - self.t:
                acss_signal.set()
            if len(outputs) == self.n:
                return

    async def run_multiply(self, left_inputs, right_inputs):
        start = time.time()
        values = {
            "commitment": left_inputs["commitment"] + right_inputs["commitment"],
            "proof": left_inputs["proof"] + right_inputs["proof"],
        }
        serialized_values = json.dumps(values).encode("utf-8")

        acss_outputs = {}
        acss_signal = asyncio.Event()
        logger.info(
            "[%d] Starting static Dumbo-BGW degree reduction for %d multiplication gates",
            self.my_id,
            self.batchsize,
        )
        self.acss_task = asyncio.create_task(
            self.acss_step(acss_outputs, serialized_values, acss_signal)
        )
        await acss_signal.wait()
        acss_signal.clear()

        key_proposal = list(acss_outputs.keys())
        acssend = self.get_send(StaticBGWReductionMsg.ACS)
        acsrecv = self.subscribe_recv(StaticBGWReductionMsg.ACS)
        leader = 1
        acs = OptimalCommonSet(
            StaticBGWReductionMsg.ACS,
            self.my_id,
            self.n,
            self.t,
            leader,
            key_proposal,
            self.pkbls,
            self.skbls,
            acssend,
            acsrecv,
            acss_outputs,
            acss_signal,
        )
        try:
            acsset = await acs.handle_message()
        finally:
            try:
                acs.subscribe_recv_task.cancel()
            except Exception:
                pass

        common = sorted(list(acsset))
        ser_common = json.dumps(common).encode("utf-8")
        commits_sel = [json.loads(acss_outputs[i]["commits"].decode()) for i in common]
        shares_sel = [json.loads(acss_outputs[i]["shares"].decode()) for i in common]
        ser_commit = json.dumps(commits_sel).encode("utf-8")
        ser_share = json.dumps(shares_sel).encode("utf-8")

        interpolated = lib.pyInterpolateShareswithTransfer(
            ser_common, ser_commit, ser_share
        )
        result = json.loads(interpolated.decode("utf-8"))
        if "shares" in result:
            result["proof"] = result.pop("shares")

        elapsed = time.time() - start
        logger.info(
            "[%d] Static Dumbo-BGW degree reduction finished; gates=%d, common=%s, time=%s",
            self.my_id,
            self.batchsize,
            common,
            elapsed,
        )
        return result
