from adkg.polynomial import polynomials_over
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Pre, ACSS_Foll, ACSS_Fluid_Pre, ACSS_Fluid_Foll

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial

import math

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)


def batchbundle_output_count(t):
    """Return the number of Bundle outputs extracted from one BACSS batch."""
    if not isinstance(t, int) or t < 0:
        raise ValueError("BatchBundle threshold must be a non-negative integer")
    return t + 1


def batchbundle_batch_count(value_count, t):
    """Return the paper-faithful number of BACSS batches for ``value_count``."""
    if not isinstance(value_count, int) or value_count < 0:
        raise ValueError("BatchBundle value_count must be a non-negative integer")
    return max(1, math.ceil(value_count / batchbundle_output_count(t)))


def batchbundle_extraction_matrix(field, t):
    """Build Algorithm 3's (t+1)-by-(2t+1) MDS extraction matrix."""
    output_count = batchbundle_output_count(t)
    input_count = 2 * t + 1
    return [
        [field(column + 1) ** row for column in range(input_count)]
        for row in range(output_count)
    ]

class RANDMsgType:
    ACSS = "GR.A"
    RBC = "GR.R"
    ABA = "GR.B"
    PREKEY = "GR.P"
    KEY = "GR.K"
    MASK = "GR.M"
    GENRAND = "GR.GR"
    ROBUSTREC = "GR.RR"
    TRANS = "GR.TR"
    APREP = "GR.AP"

    
class Bundle:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrix

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()


        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
            
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("ADKG task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, outputs, values, acss_signal):

        acsstag = RANDMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         )
        self.acss_tasks = [None] * self.n
        #  n-parallel ACSS
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_bundle(0, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_bundle(0, dealer_id=i))

        while True:
            (dealer, _, shares, commitments, w_list) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments, 'w_list': w_list}

            if len(outputs) >= self.n - self.t:

                acss_signal.set()

            if len(outputs) == self.n:
                return    

    async def commonsubset(self, rbc_out, acss_outputs, acss_signal, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            rbcl = await rbc_out[j].get()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                acss_signal.clear()
                for k in rbc_values[j]:
                    if k not in acss_outputs.keys():
                        subset = False
                if subset:
                    coin_keys[j]((acss_outputs, rbc_values[j]))
                    return
                await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None

        rbc_signal.set()
    
    async def agreement(self, key_proposal, acss_outputs, acss_signal):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        async def predicate(_key_proposal):
            kp = Bitmap(self.n, _key_proposal)
            kpl = []
            for ii in range(self.n):
                if kp.get_bit(ii):
                    kpl.append(ii)
            if len(kpl) <= self.t:
                return False
        
            while True:
                subset = True
                for kk in kpl:
                    if kk not in acss_outputs.keys():
                        subset = False
                if subset:
                    acss_signal.clear()    
                    return True
                acss_signal.clear()
                await acss_signal.wait()

        async def _setup(j):
            
            # starting RBC
            rbctag =RANDMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)


            asyncio.create_task(
                optqrbc(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                )
            )

            abatag = RANDMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(self.n):
                    abasend(i, o)
                
            aba_task = asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    self.n,
                    self.t,
                    coin_keys[j].get,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
            return aba_task

        work_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])
        
        rbc_signal = asyncio.Event()
        rbc_values = [None for i in range(self.n)]

        return (
            self.commonsubset(
                rbc_outputs,
                acss_outputs,
                acss_signal,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.generate_rand(
                acss_outputs,
                acss_signal,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def generate_rand(self, acss_outputs, acss_signal, rbc_values, rbc_signal):
        await rbc_signal.wait()
        rbc_signal.clear()


        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        
        # Waiting for all ACSS to terminate
        for k in self.mks:
            if k not in acss_outputs:
                await acss_signal.wait()
                acss_signal.clear()

        secrets = [[self.ZR(0)]*self.n for _ in range(self.rand_num)]
        w_lists = {}

        for idx in range(self.rand_num):
            for node in range(self.n):
                if node in self.mks:
                    secrets[idx][node] = acss_outputs[node]['shares']['msg'][0][idx]
                    w_lists[node] = acss_outputs[node]['w_list']
        
        z_shares = [[self.ZR(0) for _ in range(self.n-self.t)] for _ in range(self.rand_num)]

        for i in range(self.rand_num): 
            for j in range(self.n-self.t): 
                z_shares[i][j] = self.dotprod(self.matrix[j], secrets[i])
        return (self.mks, z_shares, w_lists)
    
    async def run_bundle(self, w, rounds):
        import time
        start_time = time.time()

        acss_outputs = {}
        acss_signal = asyncio.Event()
   
        self.rand_num = rounds * 2  
        values = [self.ZR.rand() for _ in range(rounds*2)]  
        
        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        
        key_proposal = list(acss_outputs.keys())

        # MVBA
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, acss_outputs, acss_signal))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        mks, new_shares, w_list = output
        rand_shares = []
        for i in range(self.rand_num): 
            if i == self.rand_num - 1: 
                w = w - i * (self.n - self.t)
                rand_shares = rand_shares + new_shares[i][:w]
            else: 
                rand_shares = rand_shares + new_shares[i]

        duration = time.time() - start_time
        print(f"my id: {self.my_id} RAND protocol total time: {duration:.4f} seconds")

        self.output_queue.put_nowait(rand_shares)
        return rand_shares, w_list


class Bundle_Pre(Bundle):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):

        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)
        if self.n != 3 * self.t + 1:
            raise ValueError(
                "AD-MPC BatchBundle requires the paper parameter n=3*t+1"
            )
        

    async def run_bundle(self, w, rounds=None):
        expected_rounds = batchbundle_batch_count(w, self.t)
        if rounds is None:
            rounds = expected_rounds
        if rounds != expected_rounds:
            raise ValueError(
                "BatchBundle rounds must be ceil(w/(t+1)): "
                f"expected {expected_rounds}, got {rounds}"
            )
        self.rand_num = rounds * 2
        values = [self.ZR.rand() for _ in range(rounds*2)]
        self.acss_task = asyncio.create_task(self.acss_step(values))
        
    async def acss_step(self, values):

        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       

        acsstag = RANDMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

        self.acss = ACSS_Pre(pks_next_layer, 
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss.metrics_protocol = "randgen"
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_bundle(0, values=values))
         
class Bundle_Foll(Bundle):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        self.mpc_instance = mpc_instance
        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)
        if self.n != 3 * self.t + 1:
            raise ValueError(
                "AD-MPC BatchBundle requires the paper parameter n=3*t+1"
            )
        self.quorum_size = self.n - self.t
        self.outputs_per_batch = batchbundle_output_count(self.t)
        self.bundle_extraction_matrix = batchbundle_extraction_matrix(
            self.ZR, self.t
        )
        self.acss_instances = []
        self.rbc_tasks = []

    def kill(self):
        subscribe_task = getattr(self, "subscribe_recv_task", None)
        if subscribe_task is not None:
            subscribe_task.cancel()
        for task in getattr(self, "acss_tasks", ()):
            if task is not None:
                task.cancel()
        for task in getattr(self, "rbc_tasks", ()):
            if task is not None:
                task.cancel()
        collector = getattr(self, "acss_task", None)
        if collector is not None:
            collector.cancel()
        for acss in getattr(self, "acss_instances", ()):
            if acss is None:
                continue
            try:
                acss.kill()
            except Exception:
                logger.debug(
                    "BatchBundle ACSS instance already stopped",
                    exc_info=True,
                )

    def _encode_proposal(self, proposal):
        proposal = tuple(int(dealer) for dealer in proposal)
        if (
            len(proposal) != self.quorum_size
            or len(set(proposal)) != self.quorum_size
            or any(dealer < 0 or dealer >= self.n for dealer in proposal)
        ):
            raise ValueError(
                "BatchBundle proposal must contain exactly "
                f"n-t={self.quorum_size} unique dealer IDs"
            )
        bitmap = Bitmap(self.n)
        for dealer in proposal:
            bitmap.set_bit(dealer)
        return bytes(bitmap.array)

    def _decode_proposal(self, encoded):
        if not isinstance(encoded, (bytes, bytearray)):
            return None
        expected_length = Bitmap(self.n).BYTES_LENGTH
        if len(encoded) != expected_length:
            return None
        try:
            bitmap = Bitmap(self.n, encoded)
            proposal = tuple(
                dealer for dealer in range(self.n)
                if bitmap.get_bit(dealer)
            )
        except (AssertionError, IndexError, TypeError):
            return None
        if len(proposal) != self.quorum_size:
            return None
        # Reject non-canonical encodings with set padding bits.
        if self._encode_proposal(proposal) != bytes(encoded):
            return None
        return proposal

    async def _proposal_is_valid(
            self, encoded, acss_outputs, w_outputs, dealer_ready):
        proposal = self._decode_proposal(encoded)
        if proposal is None:
            return False
        await asyncio.gather(
            *(dealer_ready[dealer].wait() for dealer in proposal)
        )
        if not all(
            dealer in acss_outputs and dealer in w_outputs
            for dealer in proposal
        ):
            raise RuntimeError(
                "BatchBundle dealer availability was signalled before its "
                "BACSS shares and commitments became available"
            )
        return True

    async def agreement_dynamic(
            self, key_proposal, acss_outputs, w_outputs, dealer_ready):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        coin_keys = [asyncio.Queue() for _ in range(self.n)]
        local_rbc_input = self._encode_proposal(key_proposal)

        async def predicate(_key_proposal):
            return await self._proposal_is_valid(
                _key_proposal, acss_outputs, w_outputs, dealer_ready
            )

        async def _setup(j):
            rbctag = RANDMsgType.RBC + str(j)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id:
                rbc_input = local_rbc_input

            self.rbc_tasks[j] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    j,
                    predicate,
                    rbc_input,
                    rbc_outputs[j].put_nowait,
                    rbcsend,
                    rbcrecv,
                    self.member_list
                )
            )

            abatag = RANDMsgType.ABA + str(j)
            abasend, abarecv = self.get_send(abatag), self.subscribe_recv(abatag)

            def bcast(o):
                for i in range(len(self.member_list)):
                    abasend(self.member_list[i], o)

            aba_task = asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    self.n,
                    self.t,
                    coin_keys[j].get,
                    aba_inputs[j].get,
                    aba_outputs[j].put_nowait,
                    bcast,
                    abarecv,
                )
            )
            return aba_task

        self.rbc_tasks = [None] * self.n
        work_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])
        rbc_signal = asyncio.Event()
        rbc_values = [None for _ in range(self.n)]

        return (
            self.commonsubset_dynamic(
                rbc_outputs,
                acss_outputs,
                w_outputs,
                dealer_ready,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.generate_rand_dynamic(
                acss_outputs,
                w_outputs,
                dealer_ready,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def run_bundle(self, w, rounds=None):
        expected_rounds = batchbundle_batch_count(w, self.t)
        if rounds is None:
            rounds = expected_rounds
        if rounds != expected_rounds:
            raise ValueError(
                "BatchBundle rounds must be ceil(w/(t+1)): "
                f"expected {expected_rounds}, got {rounds}"
            )
        print(f"bundle_foll run_bundle: w={w}, rounds={rounds}")
        self.rand_num = rounds * 2
        self.member_list = [
            self.n * self.mpc_instance.layer_ID + i
            for i in range(self.n)
        ]

        acss_outputs = {}
        w_outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(self.n)]
        quorum_proposal = asyncio.get_running_loop().create_future()
        self.acss_task = asyncio.create_task(
            self.acss_step(
                self.rand_num,
                acss_outputs,
                w_outputs,
                quorum_proposal,
                dealer_ready,
            )
        )
        key_proposal = list(await quorum_proposal)

        # MVBA
        create_acs_task = asyncio.create_task(
            self.agreement_dynamic(
                key_proposal, acss_outputs, w_outputs, dealer_ready
            )
        )
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)

        common_set, new_rand, new_hat_rand, new_w_group = output
        self.common_subset = tuple(common_set)
        generated_rand = [value for batch in new_rand for value in batch]
        generated_hat = [value for batch in new_hat_rand for value in batch]
        generated_w = [value for batch in new_w_group for value in batch]
        if min(len(generated_rand), len(generated_hat), len(generated_w)) < w:
            raise RuntimeError(
                "BatchBundle generated fewer tuples than requested: "
                f"rand={len(generated_rand)}, hat={len(generated_hat)}, "
                f"W={len(generated_w)}, expected={w}"
            )
        return generated_rand[:w], generated_hat[:w], generated_w[:w]

    async def commonsubset_dynamic(
            self, rbc_out, acss_outputs, w_outputs, dealer_ready,
            rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            rbcl = await rbc_out[j].get()
            proposal = self._decode_proposal(rbcl)
            if proposal is None:
                raise ValueError("RBC returned an invalid BatchBundle proposal")
            rbc_values[j] = list(proposal)

            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)

            await asyncio.gather(
                *(dealer_ready[dealer].wait() for dealer in proposal)
            )
            if not all(
                dealer in acss_outputs and dealer in w_outputs
                for dealer in proposal
            ):
                raise RuntimeError(
                    "BatchBundle RBC proposal became ready before all local "
                    "BACSS shares and commitments were stored"
                )
            coin_keys[j]((acss_outputs, rbc_values[j]))

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            aba_values[j] = await aba_out[j]()  # May block

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        await asyncio.gather(*[
            asyncio.create_task(_recv_aba(j)) for j in range(self.n)
        ])
        assert sum(aba_values) >= 1

        cancelled_rbc_receivers = []
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                cancelled_rbc_receivers.append(r_threads[j])
                rbc_values[j] = None
        if cancelled_rbc_receivers:
            await asyncio.gather(
                *cancelled_rbc_receivers, return_exceptions=True
            )

        rbc_signal.set()

    def _select_common_set(self, rbc_values):
        for proposal in rbc_values:
            if proposal is None:
                continue
            common_set = tuple(proposal)
            try:
                self._encode_proposal(common_set)
            except ValueError as exc:
                raise RuntimeError(
                    "Agreed BatchBundle proposal is not an exact valid quorum"
                ) from exc
            return common_set
        raise RuntimeError("BatchBundle agreement returned no accepted proposal")

    async def generate_rand_dynamic(
            self, acss_outputs, w_outputs, dealer_ready,
            rbc_values, rbc_signal):
        await rbc_signal.wait()
        common_set = self._select_common_set(rbc_values)
        await asyncio.gather(
            *(dealer_ready[dealer].wait() for dealer in common_set)
        )
        if not all(
            dealer in acss_outputs and dealer in w_outputs
            for dealer in common_set
        ):
            raise RuntimeError(
                "BatchBundle common-set dealer was signalled before its "
                "BACSS shares and commitments became available"
            )

        self.mks = set(common_set)
        batch_count = self.rand_num // 2
        flat_outputs = {}
        flat_w_outputs = {}
        for dealer in common_set:
            shares = [
                share
                for share_row in acss_outputs[dealer]
                for share in share_row
            ]
            if len(shares) != self.rand_num:
                raise RuntimeError(
                    f"BatchBundle dealer {dealer} returned {len(shares)} "
                    f"shares, expected {self.rand_num}"
                )
            commitments = [
                commitment
                for commitment_row in w_outputs[dealer]
                for commitment in commitment_row
            ]
            if len(commitments) != batch_count:
                raise RuntimeError(
                    f"BatchBundle dealer {dealer} returned "
                    f"{len(commitments)} W commitments, expected "
                    f"{batch_count}"
                )
            flat_outputs[dealer] = shares
            flat_w_outputs[dealer] = commitments

        new_rand = []
        new_hat_rand = []
        new_w_group = []
        for batch_index in range(batch_count):
            rand_inputs = [
                flat_outputs[dealer][batch_index]
                for dealer in common_set
            ]
            hat_inputs = [
                flat_outputs[dealer][batch_count + batch_index]
                for dealer in common_set
            ]
            commitment_inputs = [
                flat_w_outputs[dealer][batch_index]
                for dealer in common_set
            ]
            new_rand.append([
                self.dotprod(row, rand_inputs)
                for row in self.bundle_extraction_matrix
            ])
            new_hat_rand.append([
                self.dotprod(row, hat_inputs)
                for row in self.bundle_extraction_matrix
            ])
            new_w_group.append([
                self.multiexp(commitment_inputs, row)
                for row in self.bundle_extraction_matrix
            ])
        return common_set, new_rand, new_hat_rand, new_w_group

    async def acss_step(
            self, secret_count, outputs, w_outputs,
            quorum_proposal, dealer_ready):
        self.acss_tasks = [None] * self.n
        self.acss_instances = [None] * self.n

        async def _run_dealer(dealer_id, acss):
            try:
                result = await acss.avss_bundle(0, dealer_id, secret_count)
                if result[0] != dealer_id:
                    raise ValueError(
                        "BatchBundle BACSS returned dealer %s for task %s"
                        % (result[0], dealer_id)
                    )
                return dealer_id, result, None
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                return dealer_id, None, exc

        for dealer_id in range(self.n):
            acsstag = RANDMsgType.ACSS + str(self.mpc_instance.layer_ID - 1) + str(dealer_id)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            acss = ACSS_Foll(
                self.public_keys, self.private_key,
                self.g, self.h, self.n, self.t, self.deg, self.sc,
                self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1,
                mpc_instance=self.mpc_instance,
            )
            acss.metrics_protocol = getattr(
                self, "metrics_protocol", "randgen"
            )
            self.acss = acss
            self.acss_instances[dealer_id] = acss
            self.acss_tasks[dealer_id] = asyncio.create_task(
                _run_dealer(dealer_id, acss)
            )

        for completed in asyncio.as_completed(self.acss_tasks):
            dealer, result, error = await completed
            if error is not None:
                logger.warning(
                    "[%d] BatchBundle rejected dealer %d: %s",
                    self.my_id,
                    dealer,
                    error,
                )
                continue

            _, _, share_info, _, dealer_w_outputs = result
            outputs[dealer] = share_info['msg']
            w_outputs[dealer] = dealer_w_outputs
            dealer_ready[dealer].set()

            if (
                len(outputs) >= self.quorum_size
                and not quorum_proposal.done()
            ):
                quorum_proposal.set_result(
                    tuple(sorted(outputs)[:self.quorum_size])
                )

        if not quorum_proposal.done():
            quorum_proposal.set_exception(RuntimeError(
                "BatchBundle exhausted all dealer tasks before collecting "
                f"n-t={self.quorum_size} valid outputs"
            ))
