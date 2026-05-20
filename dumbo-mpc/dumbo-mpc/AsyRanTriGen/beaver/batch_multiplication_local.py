import asyncio
import json
import logging
import time
from ctypes import CDLL, c_char_p, c_int, c_void_p, string_at

from Crypto.Util.number import long_to_bytes

from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.hbacss import Hbacss1
from beaver.utils.misc import subscribe_recv, wrap_send


logger = logging.getLogger(__name__)

lib_bulletproof = CDLL("./libbulletproofs_amcl.so")
lib_bulletproof.pyProveFactors.argtypes = [c_char_p]
lib_bulletproof.pyProveFactors.restype = c_void_p
lib_bulletproof.pyFreeString.argtypes = [c_void_p]
lib_bulletproof.pyFreeString.restype = None

lib = CDLL("./kzg_ped_out.so")
lib.pyMultiplyClaimedValuesWithAux.argtypes = [c_char_p, c_char_p]
lib.pyMultiplyClaimedValuesWithAux.restype = c_char_p
lib.pyInterpolateShareswithTransfer.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyInterpolateShareswithTransfer.restype = c_char_p
if hasattr(lib, "pySetN"):
    lib.pySetN.argtypes = [c_int]
    lib.pySetN.restype = None


class BatchMulLocalMsg:
    ACSS = "BML_ACSS"
    ACS = "BML_ACS"


class BatchMulLocal:
    """BatchMul variant whose output stays in the current committee."""

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
        self.acss = None
        self.acss_tasks = []
        self.acss_task = None

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
                logger.debug("[%d] BatchMulLocal ACSS cleanup raised", self.my_id, exc_info=True)
        if self.acss_task is not None:
            self.acss_task.cancel()

    def _build_product_payload(self, left_inputs, right_inputs):
        serialized_left_proof = json.dumps(left_inputs["proof"]).encode("utf-8")
        serialized_right_proof = json.dumps(right_inputs["proof"]).encode("utf-8")

        result = lib.pyMultiplyClaimedValuesWithAux(
            serialized_left_proof, serialized_right_proof
        )
        deser_result = json.loads(result.decode("utf-8"))
        secrets = deser_result["value"]
        secrets_aux = deser_result["aux"]

        left_proof = json.loads(serialized_left_proof.decode("utf-8"))
        right_proof = json.loads(serialized_right_proof.decode("utf-8"))
        left_vec = [int(entry["ClaimedValue"]) for entry in left_proof]
        right_vec = [int(entry["ClaimedValue"]) for entry in right_proof]
        out_vec = [int(x) for x in secrets]
        left_aux_vec = [int(entry["ClaimedValueAux"]) for entry in left_proof]
        right_aux_vec = [int(entry["ClaimedValueAux"]) for entry in right_proof]
        out_aux_vec = [int(x) for x in secrets_aux]

        pk_dict = json.loads(self.srs["Pk"].decode("utf-8"))
        g0 = pk_dict["G1_g"][0]
        h0 = pk_dict["G1_h"][0]

        gx_bytes = long_to_bytes(int(g0["X"]), 48)
        gy_bytes = long_to_bytes(int(g0["Y"]), 48)
        hx_bytes = long_to_bytes(int(h0["X"]), 48)
        hy_bytes = long_to_bytes(int(h0["Y"]), 48)
        uncompressed_g_hex = (b"\x04" + gx_bytes + gy_bytes).hex()
        uncompressed_h_hex = (b"\x04" + hx_bytes + hy_bytes).hex()

        witnesses = []
        for p_dec, q_dec, r_dec, p_blind_dec, q_blind_dec, r_blind_dec in zip(
            left_vec,
            right_vec,
            out_vec,
            left_aux_vec,
            right_aux_vec,
            out_aux_vec,
        ):
            witnesses.append(
                {
                    "p": hex(p_dec)[2:],
                    "q": hex(q_dec)[2:],
                    "r": hex(r_dec)[2:],
                    "p_blind": hex(p_blind_dec)[2:],
                    "q_blind": hex(q_blind_dec)[2:],
                    "r_blind": hex(r_blind_dec)[2:],
                }
            )

        prove_input = {
            "witnesses": witnesses,
            "g": uncompressed_g_hex,
            "h": uncompressed_h_hex,
        }
        proof_ptr = lib_bulletproof.pyProveFactors(
            json.dumps(prove_input).encode("utf-8")
        )
        try:
            proof_res = json.loads(string_at(proof_ptr).decode("utf-8"))
        finally:
            if proof_ptr:
                lib_bulletproof.pyFreeString(proof_ptr)

        proof = proof_res["proof"]
        logger.info(
            "[%d] BatchMulLocal proof size bytes: %d",
            self.my_id,
            len(proof) // 2,
        )
        return {
            "left": left_inputs,
            "right": right_inputs,
            "result": deser_result,
            "proof": proof,
        }

    async def acss_step(self, outputs, values, acss_signal):
        layer_id = self.mpc_instance.layer_ID
        acsstag = BatchMulLocalMsg.ACSS + str(layer_id)
        acsssend = self.get_send(acsstag)
        acssrecv = self.subscribe_recv(acsstag)

        self.acss = Hbacss1(
            self.public_keys,
            self.private_key,
            self.srs,
            self.n,
            self.t,
            self.my_id,
            acsssend,
            acssrecv,
            "avss_with_aggbatch_multiplication",
        )
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n):
            if dealer_id == self.my_id:
                self.acss_tasks[dealer_id] = asyncio.create_task(
                    self.acss.avss(0, coms=None, values=values)
                )
            else:
                self.acss_tasks[dealer_id] = asyncio.create_task(
                    self.acss.avss(0, coms=None, dealer_id=dealer_id)
                )

        majority_oc = None
        while True:
            try:
                (
                    dealer,
                    _,
                    shares,
                    commitments,
                    left_commitments,
                    right_commitments,
                ) = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("[%d] BatchMulLocal ACSS output handling failed", self.my_id)
                continue

            outputs[dealer] = {
                "shares": shares,
                "commits": commitments,
                "left_commitments": left_commitments,
                "right_commitments": right_commitments,
            }

            if majority_oc is not None:
                if (left_commitments, right_commitments) != majority_oc:
                    outputs.pop(dealer, None)
                    continue
                acss_signal.set()
            else:
                commit_counter = {}
                for value in outputs.values():
                    key = (value["left_commitments"], value["right_commitments"])
                    commit_counter[key] = commit_counter.get(key, 0) + 1
                for oc_val, count in commit_counter.items():
                    if count >= self.n - self.t:
                        majority_oc = oc_val
                        for del_dealer in list(outputs.keys()):
                            key = (
                                outputs[del_dealer]["left_commitments"],
                                outputs[del_dealer]["right_commitments"],
                            )
                            if key != majority_oc:
                                outputs.pop(del_dealer, None)
                        acss_signal.set()
                        break

            if len(outputs) == self.n:
                return

    async def run_multiply(self, left_inputs, right_inputs):
        if len(left_inputs["proof"]) != self.batchsize:
            raise ValueError("left input width does not match BatchMulLocal batchsize")
        if len(right_inputs["proof"]) != self.batchsize:
            raise ValueError("right input width does not match BatchMulLocal batchsize")

        start = time.time()
        payload = self._build_product_payload(left_inputs, right_inputs)

        acss_outputs = {}
        acss_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(
            self.acss_step(acss_outputs, payload, acss_signal)
        )
        await acss_signal.wait()
        acss_signal.clear()

        key_proposal = list(acss_outputs.keys())
        layer_id = self.mpc_instance.layer_ID
        acstag = BatchMulLocalMsg.ACS + str(layer_id)
        acssend = self.get_send(acstag)
        acsrecv = self.subscribe_recv(acstag)

        acs = OptimalCommonSet(
            acstag,
            self.my_id,
            self.n,
            self.t,
            1,
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
            "[%d] BatchMulLocal finished; gates=%d, time=%s",
            self.my_id,
            self.batchsize,
            elapsed,
        )
        return result
