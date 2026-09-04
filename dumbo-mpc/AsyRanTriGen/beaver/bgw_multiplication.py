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


class BGWReductionMsg:
    ACSS = "BGW_ACSS"
    ACS = "BGW_ACS"


class BGWReduction:
    """Dumbo-MPC BGW degree reduction, packaged as a Continuum component.

    The dynamic runner has n * layers global processes. Dumbo's Hbacss1 is a
    static committee protocol and expects local party ids 0..n-1, so this
    wrapper maps local destinations to the current layer's global process ids.
    """

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
        mpc_instance,
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
        self.mpc_instance = mpc_instance

        if hasattr(lib, "pySetN"):
            lib.pySetN(self.n)

        layer_base = self.mpc_instance.layer_ID * self.n

        def local_send(dest, message):
            send(layer_base + dest, message)

        async def local_recv():
            sender, message = await recv()
            return sender % self.n, message

        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(local_recv)

        def _send(tag):
            return wrap_send(tag, local_send)

        self.get_send = _send
        self.acss_tasks = []
        self.acss_task = None
        self.acss = None

    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in self.acss_tasks:
            if task is not None:
                task.cancel()
        if self.acss is not None:
            try:
                self.acss.kill()
            except Exception:
                logger.debug("[%d] BGW ACSS cleanup raised", self.my_id, exc_info=True)
        if self.acss_task is not None:
            self.acss_task.cancel()

    async def acss_step(
        self, outputs, values, quorum_proposal, acss_signal
    ):
        acsssend = self.get_send(BGWReductionMsg.ACSS)
        acssrecv = self.subscribe_recv(BGWReductionMsg.ACSS)

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
        # Hbacss1 predates the communication-metrics plumbing used by the
        # dynamic protocols.  Attach the owning MPC instance so its dealer
        # payload calibration is recorded under the M_BGW_* tag.
        self.acss.mpc_instance = self.mpc_instance
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
                logger.exception("[%d] BGW ACSS output handling failed", self.my_id)
                continue

            outputs[dealer] = {"shares": shares, "commits": commitments}
            if len(outputs) >= self.n - self.t:
                acss_signal.set()
                if not quorum_proposal.done():
                    # Freeze the protocol input at the first n-t verified
                    # outputs.  Later dealers remain available to OCS, but
                    # cannot race into this party's initial proposal or the
                    # paper computation quorum.
                    frozen_proposal = tuple(
                        sorted(outputs)[:self.n - self.t]
                    )
                    metrics_recorder = getattr(
                        self.mpc_instance, "metrics_recorder", None
                    )
                    record_proof_quorum = getattr(
                        metrics_recorder, "record_proof_quorum", None
                    )
                    if callable(record_proof_quorum):
                        record_proof_quorum(
                            protocol="bgw",
                            target_layer=self.mpc_instance.layer_ID,
                            receiver_local_id=self.my_id,
                            dealer_ids=frozen_proposal,
                            required_count=self.n - self.t,
                        )
                    quorum_proposal.set_result(frozen_proposal)
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
        quorum_proposal = asyncio.get_running_loop().create_future()
        acss_signal = asyncio.Event()
        logger.info(
            "[%d] Starting Dumbo-BGW degree reduction for %d multiplication gates",
            self.my_id,
            self.batchsize,
        )
        self.acss_task = asyncio.create_task(
            self.acss_step(
                acss_outputs, serialized_values, quorum_proposal, acss_signal
            )
        )
        key_proposal = list(await quorum_proposal)
        acss_signal.clear()

        acssend = self.get_send(BGWReductionMsg.ACS)
        acsrecv = self.subscribe_recv(BGWReductionMsg.ACS)
        leader = 1
        acs = OptimalCommonSet(
            BGWReductionMsg.ACS,
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
        acsset = await acs.handle_message()
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
            "[%d] Dumbo-BGW degree reduction finished; gates=%d, time=%s",
            self.my_id,
            self.batchsize,
            elapsed,
        )
        return result
