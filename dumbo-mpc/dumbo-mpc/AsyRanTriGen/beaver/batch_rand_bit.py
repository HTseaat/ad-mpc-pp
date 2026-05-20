import asyncio
import json
import logging
import time
from ctypes import CDLL, c_char_p, c_int

from beaver.broadcast.otmvba_dyn import OptimalCommonSet
from beaver.hbacss import ACSS_Foll, ACSS_Pre
from beaver.utils.misc import subscribe_recv, wrap_send
from optimizedhbmpc.elliptic_curve import Subgroup


logger = logging.getLogger(__name__)

FIELD_MODULUS = int(Subgroup.BLS12_381)
RANDBIT_EXTRA_CANDIDATES = 4

lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p
lib.VMmatrixGen.argtypes = [c_int]
lib.VMmatrixGen.restype = c_char_p
lib.pyRandomShareCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyRandomShareCompute.restype = c_char_p
if hasattr(lib, "pySetN"):
    lib.pySetN.argtypes = [c_int]
    lib.pySetN.restype = None


class BatchRandBitMsg:
    ACSS = "RB_ACSS"
    ACS = "RB_ACS"


class _BatchRandBitBase:
    def __init__(
        self,
        public_keys,
        private_key,
        n,
        t,
        srs,
        my_id,
        send,
        recv,
        bit_num,
        mpc_instance,
    ):
        self.public_keys = public_keys
        self.private_key = private_key
        self.n = n
        self.t = t
        self.srs = srs
        self.my_id = my_id
        self.send = send
        self.recv = recv
        self.bit_num = bit_num
        self.mpc_instance = mpc_instance
        self.acss = None
        self.acss_tasks = []
        self.acss_task = None
        self.pkbls = getattr(mpc_instance, "pkbls", None)
        self.skbls = getattr(mpc_instance, "skbls", None)

        if hasattr(lib, "pySetN"):
            lib.pySetN(self.n)
        self.matrix = lib.VMmatrixGen(self.t)

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
        if self.acss_task is not None:
            self.acss_task.cancel()
        if self.acss is not None:
            try:
                self.acss.kill()
            except Exception:
                logger.debug("[%d] BatchRandBit ACSS cleanup raised", self.my_id, exc_info=True)

    def _random_rounds(self):
        target = self.bit_num + max(RANDBIT_EXTRA_CANDIDATES, self.t + 1)
        return (target + self.t) // (self.t + 1)

    def _random_capacity(self):
        return self._random_rounds() * (self.t + 1)

    def _select_values(self, values, indices):
        return {
            "commitment": [values["commitment"][i] for i in indices],
            "proof": [values["proof"][i] for i in indices],
        }

    def _extract_random_shares(self, common, outputs):
        serialized_common = json.dumps(common).encode("utf-8")
        commitments = [None] * self.n
        proofsandshares = [None] * self.n
        for dealer_id in common:
            commitments[dealer_id] = json.loads(
                outputs[dealer_id]["commits"].decode("utf-8")
            )
            proofsandshares[dealer_id] = json.loads(
                outputs[dealer_id]["shares"].decode("utf-8")
            )

        result = lib.pyRandomShareCompute(
            self.matrix,
            serialized_common,
            json.dumps(commitments).encode("utf-8"),
            json.dumps(proofsandshares).encode("utf-8"),
            self.t,
        )
        decoded = json.loads(result.decode("utf-8"))
        return {
            "commitment": decoded["commitment"][: self._random_capacity()],
            "proof": decoded["proof"][: self._random_capacity()],
        }

    @staticmethod
    def _mod_sqrt(value):
        value %= FIELD_MODULUS
        if value == 0:
            return 0
        if pow(value, (FIELD_MODULUS - 1) // 2, FIELD_MODULUS) != 1:
            return None

        q = FIELD_MODULUS - 1
        s = 0
        while q % 2 == 0:
            s += 1
            q //= 2

        z = 2
        while pow(z, (FIELD_MODULUS - 1) // 2, FIELD_MODULUS) != FIELD_MODULUS - 1:
            z += 1

        m = s
        c = pow(z, q, FIELD_MODULUS)
        t = pow(value, q, FIELD_MODULUS)
        r = pow(value, (q + 1) // 2, FIELD_MODULUS)

        while t != 1:
            i = 1
            t2i = pow(t, 2, FIELD_MODULUS)
            while t2i != 1:
                i += 1
                t2i = pow(t2i, 2, FIELD_MODULUS)
                if i >= m:
                    return None
            b = pow(c, 1 << (m - i - 1), FIELD_MODULUS)
            m = i
            c = (b * b) % FIELD_MODULUS
            t = (t * c) % FIELD_MODULUS
            r = (r * b) % FIELD_MODULUS

        return r

    def _scale_values_elementwise(self, values, coeffs):
        if len(values["proof"]) != len(coeffs):
            raise ValueError("value/coefficient length mismatch")
        if not hasattr(self.mpc_instance, "_linear_comb"):
            raise RuntimeError("mpc instance does not support public linear combinations")

        commitments = []
        proofs = []
        for idx, coeff in enumerate(coeffs):
            scaled = self.mpc_instance._linear_comb(
                [self._select_values(values, [idx])],
                [coeff],
            )
            commitments.append(scaled["commitment"][0])
            proofs.append(scaled["proof"][0])
        return {"commitment": commitments, "proof": proofs}


class BatchRandBit_Pre(_BatchRandBitBase):
    """Share locally sampled random field elements to the next committee."""

    async def run_randbit(self):
        rounds = self._random_rounds()
        values = lib.pySampleSecret(rounds)

        start = time.time()
        layer_id = self.mpc_instance.layer_ID
        acsstag = BatchRandBitMsg.ACSS + str(layer_id + 1)
        acsssend = self.get_send(acsstag)
        acssrecv = self.subscribe_recv(acsstag)

        self.acss = ACSS_Pre(
            self.public_keys,
            self.private_key,
            self.srs,
            self.n,
            self.t,
            self.my_id,
            acsssend,
            acssrecv,
            "avss_without_proof",
            mpc_instance=self.mpc_instance,
        )
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(
            self.acss.avss(0, coms=None, values=values)
        )
        await self.acss_tasks[self.my_id]
        elapsed = time.time() - start
        logger.info(
            "layer ID: %s randbit_pre_time: %s, random_rounds: %s, target_signs: %s",
            layer_id,
            elapsed,
            rounds,
            self.bit_num,
        )


class BatchRandBit_Foll(_BatchRandBitBase):
    """Receive random shares and normalize them to shared signs in {-1, 1}."""

    async def _collect_acss_outputs(self, outputs, acss_signal, dealer_threshold):
        layer_id = self.mpc_instance.layer_ID
        while True:
            try:
                dealer, _, shares, commitments = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "layer ID: %s failed receiving selector bits", layer_id
                )
                continue

            outputs[dealer] = {"shares": shares, "commits": commitments}
            if len(outputs) >= dealer_threshold:
                acss_signal.set()

            if len(outputs) == self.n:
                return

    async def run_randbit(self):
        dealer_threshold = self.n - self.t
        rounds = self._random_rounds()
        start = time.time()
        layer_id = self.mpc_instance.layer_ID
        acsstag = BatchRandBitMsg.ACSS + str(layer_id)
        acsssend = self.get_send(acsstag)
        acssrecv = self.subscribe_recv(acsstag)

        self.acss = ACSS_Foll(
            self.public_keys,
            self.private_key,
            self.srs,
            self.n,
            self.t,
            self.my_id,
            acsssend,
            acssrecv,
            "avss_without_proof",
            mpc_instance=self.mpc_instance,
        )
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n):
            self.acss_tasks[dealer_id] = asyncio.create_task(
                self.acss.avss(0, rounds, coms=None, dealer_id=dealer_id)
            )

        outputs = {}
        acss_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(
            self._collect_acss_outputs(outputs, acss_signal, dealer_threshold)
        )

        await acss_signal.wait()
        acss_signal.clear()
        key_proposal = list(outputs.keys())

        acstag = BatchRandBitMsg.ACS + str(layer_id)
        acssend = self.get_send(acstag)
        acsrecv = self.subscribe_recv(acstag)
        member_list = [self.n * layer_id + i for i in range(self.n)]
        leader = 1 if self.n > 1 else 0

        logger.info(
            "layer ID: %s randbit ACS proposal from node %s: %s",
            layer_id,
            self.my_id,
            key_proposal,
        )
        acs = OptimalCommonSet(
            acstag,
            self.my_id,
            self.n,
            self.t,
            leader,
            key_proposal,
            self.pkbls,
            self.skbls,
            acssend,
            acsrecv,
            outputs,
            acss_signal,
            member_list,
        )
        acs_start = time.time()
        acsset = await acs.handle_message_dyn()
        common = sorted(list(acsset))

        common_set = set(common)
        while not common_set.issubset(outputs.keys()):
            acss_signal.clear()
            if common_set.issubset(outputs.keys()):
                break
            await acss_signal.wait()

        random_values = self._extract_random_shares(common, outputs)
        squares = await self.mpc_instance._run_local_batchmul(
            random_values,
            random_values,
            len(random_values["proof"]),
        )
        square_shares = [int(entry["ClaimedValue"]) for entry in squares["proof"]]
        opened_squares = await self.mpc_instance.reconstruct_values(square_shares)

        selected_indices = []
        inv_roots = []
        discarded_zeroes = 0
        for idx, opened in enumerate(opened_squares):
            square = int(opened) % FIELD_MODULUS
            if square == 0:
                discarded_zeroes += 1
                continue
            root = self._mod_sqrt(square)
            if root is None:
                raise RuntimeError("opened random square is not a quadratic residue")
            selected_indices.append(idx)
            inv_roots.append(pow(root, FIELD_MODULUS - 2, FIELD_MODULUS))
            if len(selected_indices) == self.bit_num:
                break

        if len(selected_indices) < self.bit_num:
            raise RuntimeError(
                "not enough nonzero random signs generated "
                f"needed={self.bit_num}, got={len(selected_indices)}"
            )

        selected_randoms = self._select_values(random_values, selected_indices)
        signs = self._scale_values_elementwise(selected_randoms, inv_roots)

        elapsed = time.time() - start
        logger.info(
            "layer ID: %s randbit_foll_time: %s, signs: %s, candidates: %s, discarded_zeroes: %s, dealers: %s/%s",
            layer_id,
            elapsed,
            self.bit_num,
            len(random_values["proof"]),
            discarded_zeroes,
            len(common),
            self.n,
        )
        logger.info(
            "layer ID: %s randbit_acs_time: %s, common: %s",
            layer_id,
            time.time() - acs_start,
            common,
        )
        return signs
