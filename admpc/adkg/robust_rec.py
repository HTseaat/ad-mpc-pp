from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial

from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup
from adkg.progs.mixins.dataflow import Share
from adkg.robust_reconstruction import robust_reconstruct_admpc
from adkg.reed_solomon import (
    Algorithm,
    DecoderFactory,
    EncoderFactory,
    IncrementalDecoder,
    RobustDecoderFactory,
)

import math

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class ROBUSTRECMsgType:
    ACSS = "RR.A"
    RBC = "RR.R"
    ABA = "RR.B"
    PREKEY = "RR.P"
    KEY = "RR.K"
    MASK = "RR.M"
    GENRAND = "RR.GR"
    ROBUSTREC = "RR.RR"
    APREP = "RR.AP"
    

class Robust_Rec:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)


        self.global_num = 0

        

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()
        self.tagvars = {}
        self.tasks = []
        self.data = {}


        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
            
    def kill(self):
        self.subscribe_recv_task.cancel()
        for task in list(self.tasks):
            task.cancel()

    def _track_background_task(self, task):
        """Keep a live RBC responder reachable until it terminates or kill()."""
        self.tasks.append(task)

        def _task_done(completed):
            try:
                self.tasks.remove(completed)
            except ValueError:
                pass
            if not completed.cancelled():
                exception = completed.exception()
                if exception is not None:
                    logger.warning(
                        "[%d] RobustRec RBC responder failed: %s",
                        self.my_id,
                        exception,
                    )

        task.add_done_callback(_task_done)
        return task

    async def _incremental_batch_decode(self, rbc_outputs, serializer,
                                        batch_size):
        """Decode dealer vectors as their RBC instances finish.

        The dealer queue index is the Reed--Solomon evaluation-point index.  In
        particular, arrival order must never be used as a replacement dealer
        identifier.  The optimistic decoder returns after ``n-t`` consistent
        vectors.  If a vector conflicts with that candidate, later RBC outputs
        continue to be consumed until robust decoding succeeds.
        """
        if batch_size <= 0:
            return [], set(), tuple()

        field = GF(Subgroup.BLS12_381)
        point = EvalPoint(field, self.n, use_omega_powers=False)
        encoder = EncoderFactory.get(point, Algorithm.VANDERMONDE)
        decoder = DecoderFactory.get(point, Algorithm.VANDERMONDE)
        robust_decoder = RobustDecoderFactory.get(
            self.t, point, algorithm=Algorithm.GAO
        )
        incremental_decoder = IncrementalDecoder(
            encoder,
            decoder,
            robust_decoder,
            degree=self.t,
            batch_size=batch_size,
            max_errors=self.t,
        )

        expected_payload_size = batch_size * serializer.f_size
        receiver_tasks = {
            asyncio.create_task(rbc_outputs[dealer].get()): dealer
            for dealer in range(self.n)
        }
        pending = set(receiver_tasks)
        received_dealers = []

        try:
            while pending:
                completed, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                # A deterministic order is useful when several local queue
                # callbacks become ready in the same event-loop iteration.
                for receiver in sorted(
                    completed, key=lambda task: receiver_tasks[task]
                ):
                    dealer = receiver_tasks[receiver]
                    payload = receiver.result()
                    if (
                        not isinstance(payload, bytes)
                        or len(payload) != expected_payload_size
                    ):
                        logger.warning(
                            "[%d] RobustRec rejected dealer %d: expected %d "
                            "serialized bytes, got %s",
                            self.my_id,
                            dealer,
                            expected_payload_size,
                            (
                                len(payload)
                                if isinstance(payload, bytes)
                                else type(payload)
                            ),
                        )
                        continue

                    try:
                        dealer_vector = serializer.deserialize_fs(payload)
                    except Exception as exception:
                        logger.warning(
                            "[%d] RobustRec rejected dealer %d: %s",
                            self.my_id,
                            dealer,
                            exception,
                        )
                        continue
                    if len(dealer_vector) != batch_size:
                        logger.warning(
                            "[%d] RobustRec rejected dealer %d: decoded %d "
                            "values, expected %d",
                            self.my_id,
                            dealer,
                            len(dealer_vector),
                            batch_size,
                        )
                        continue

                    received_dealers.append(dealer)
                    incremental_decoder.add(
                        dealer, [int(value) for value in dealer_vector]
                    )
                    if incremental_decoder.done():
                        decoded, errors = incremental_decoder.get_results()
                        if decoded is None or len(decoded) != batch_size:
                            raise RuntimeError(
                                "RobustRec decoder returned an incomplete batch"
                            )
                        constants = [self.ZR(coefficients[0])
                                     for coefficients in decoded]
                        return constants, errors, tuple(received_dealers)
        finally:
            for receiver in pending:
                receiver.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        raise RuntimeError(
            "RobustRec exhausted all RBC outputs without reconstructing the "
            "batch"
        )
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def commonsubset(self, rbc_out, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False]*self.n
        aba_values = [0]*self.n

        async def _recv_rbc(j):
            rec_await_rbcl_time = time.time()
            rbcl = await rbc_out[j].get()
            rec_await_rbcl_time = time.time() - rec_await_rbcl_time
            print(f"rec_await_rbcl_time: {rec_await_rbcl_time}")
            rec_rbcb_time = time.time()
            rbcb = Bitmap(self.n, rbcl)
            rbc_values[j] = []
            for i in range(self.n):
                if rbcb.get_bit(i):
                    rbc_values[j].append(i)
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            rec_rbcb_time = time.time() - rec_rbcb_time
            print(f"rec_rbcb_time: {rec_rbcb_time}")
            
            subset = True
            while True:

                if subset:
                    coin_keys[j]((rbc_values[j]))
                    return
            #     await acss_signal.wait()

        r_threads = [asyncio.create_task(_recv_rbc(j)) for j in range(self.n)]

        async def _recv_aba(j):
            rec_await_aba_time = time.time()
            aba_values[j] = await aba_out[j]()  # May block
            print(f"aba_values {j}: {aba_values[j]}")
            rec_await_aba_time = time.time() - rec_await_aba_time
            print(f"rec_await_aba_time: {rec_await_aba_time}")

            if sum(aba_values) >= 1:
                # Provide 0 to all other aba
                for k in range(self.n):
                    if not aba_inputted[k]:
                        aba_inputted[k] = True
                        aba_in[k](0)
        
        rec_recv_aba_time = time.time()
        await asyncio.gather(*[asyncio.create_task(_recv_aba(j)) for j in range(self.n)])
        rec_recv_aba_time = time.time() - rec_recv_aba_time
        print(f"rec_recv_aba_time: {rec_recv_aba_time}")
        # assert sum(aba_values) >= self.n - self.t  # Must have at least N-f committed
        assert sum(aba_values) >= 1  # Must have at least N-f committed

        # Wait for the corresponding broadcasts
        rec_recv_rbc_time = time.time()
        for j in range(self.n):
            if aba_values[j]:
                await r_threads[j]
                assert rbc_values[j] is not None
            else:
                r_threads[j].cancel()
                rbc_values[j] = None
        rec_recv_rbc_time = time.time() - rec_recv_rbc_time
        print(f"rec_recv_rbc_time: {rec_recv_rbc_time}")
        rbc_signal.set()
    
    async def agreement(self, key_proposal, rbc_shares, rec_id):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        # print(f"my id: {self.my_id} rec_id: {rec_id}")

        async def predicate(_key_proposal):
            return True
            
            

        async def _setup(j):
            
            # starting RBC
            rbctag = str(self.global_num) + str(rec_id) + ROBUSTRECMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                # print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)  
                rbc_input = bytes(riv.array)
                # print(f"riv.array: {riv.array}")
                # print(f"rbc_input: {rbc_input}")

            # rbc_outputs[j] = 
            asyncio.create_task(
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

            abatag = str(self.global_num) + str(rec_id) + ROBUSTRECMsgType.ABA + str(j) # (B, msg)
            # abatag = j # (B, msg)
            abasend, abarecv =  self.get_send(abatag), self.subscribe_recv(abatag)

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

        work_tasks = await asyncio.gather(*[_setup(j) for j in range(self.n)])

        
        rbc_signal = asyncio.Event()
        rbc_values = [None for i in range(self.n)]

        return (
            self.commonsubset(
                rbc_outputs,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.robust_rec(
                rbc_values,
                rbc_signal,
                rbc_shares,
                key_proposal
            ),
            work_tasks,
        )

    async def robust_rec(self, rbc_values, rbc_signal, rbc_shares, key_proposal):
        rec_await_rbc_signal_time = time.time()
        await rbc_signal.wait()
        rbc_signal.clear()
        rec_await_rbc_signal_time = time.time() - rec_await_rbc_signal_time
        print(f"rec_await_rbc_signal_time: {rec_await_rbc_signal_time}")

        
        # print(f"rbc_values: {rbc_values}")
        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        
        
        sc_shares = [] 
        for i in range(len(rbc_shares)): 
            sc_shares.append([])
            for j in self.mks: 
                sc_shares[i].append([j+1, rbc_shares[i][j]])
        # for i in self.mks:
        #     sc_shares.append([i+1, rbc_shares[i]])
        res = [None] * len(rbc_shares)
        rec_sc_shares_time = time.time()
        for i in range(len(rbc_shares)): 
            res[i] = self.poly.interpolate_at(sc_shares[i], 0)
        # res = self.poly.interpolate_at(sc_shares, 0)
        # print(f"{self.my_id} res: {res}")
        rec_sc_shares_time = time.time() - rec_sc_shares_time
        print(f"rec_sc_shares_time: {rec_sc_shares_time}")
        return (self.mks, res)
        
    
    async def batch_run_robust_rec(
            self, rec_id, shares, member_list=None, instance_id=None):
        if not shares:
            return []
        if member_list is None:
            member_list = list(range(self.n))
        if len(member_list) != self.n or len(set(member_list)) != self.n:
            raise ValueError("RobustRec member_list must contain n unique members")
        member_list = list(member_list)
        self.member_list = member_list

        if instance_id is None:
            self.global_num += 1
            instance_tag = f"seq-{self.global_num}-rec-{rec_id}"
        else:
            instance_tag = str(instance_id)
            if not instance_tag:
                raise ValueError("RobustRec instance_id must not be empty")

        sr = Serial(self.G1)
        serialized_shares = bytes(sr.serialize_fs(shares))


        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        expected_payload_size = len(serialized_shares)

        async def predicate(message):
            return (
                isinstance(message, bytes)
                and len(message) == expected_payload_size
            )
        rec_rbc_time = time.time()
        async def _setup(j):            
            # starting RBC
            # rbctag = ROBUSTRECMsgType.ROBUSTREC + str(j)
            rbctag = (
                f"{instance_tag}:{ROBUSTRECMsgType.ROBUSTREC}:dealer-{j}"
            )
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                rbc_input = serialized_shares

            
            rbc_task = self._track_background_task(asyncio.create_task(
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
                    member_list
                )
            ))
            return rbc_task


        rbc_tasks = await asyncio.gather(*[
            _setup(j) for j in range(self.n)
        ])
        try:
            rec_values, errors, received_dealers = (
                await self._incremental_batch_decode(
                    rbc_outputs, sr, len(shares)
                )
            )
        except BaseException:
            # A cancelled/failed caller no longer needs to help finish these
            # tagged RBC instances.  On the normal fast path they deliberately
            # remain alive in the background for slower honest receivers.
            for task in rbc_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*rbc_tasks, return_exceptions=True)
            raise

        rec_rbc_time = time.time() - rec_rbc_time
        logger.debug(
            "[%d] RobustRec reconstructed batch %s from dealers %s; "
            "identified errors=%s in %.4fs",
            self.my_id,
            rec_id,
            received_dealers,
            sorted(errors),
            rec_rbc_time,
        )
        return rec_values
    
       
    
    
    async def run_robust_rec(self, rec_id, values=None, dealer_id=None):
        # self.rec_id = rec_id
        self.global_num += 1

        if values is not None:
            if dealer_id is None:
                dealer_id = self.my_id
                
            assert dealer_id == self.my_id, "Only dealer can share values."
        # If `values` is not passed then the node is a 'Recipient'
        # Verify that the `dealer_id` is not the same as `self.my_id`
        elif dealer_id is not None:
            assert dealer_id != self.my_id
        assert type(rec_id) is int

        rbctag = f"{dealer_id}-{rec_id}-B-RBC-{ROBUSTRECMsgType.ROBUSTREC}"

        broadcast_msg = None
        if self.my_id == dealer_id:
            sr = Serial(self.G1)
            serialized_shares = bytes(sr.serialize_fs(values))
            broadcast_msg = serialized_shares

        send, recv = self.get_send(rbctag), self.subscribe_recv(rbctag)

        async def predicate(_m):
            return True

        output = asyncio.Queue()
        asyncio.create_task(
        optqrbc(
            rbctag,
            self.my_id,
            self.n,
            self.t,
            dealer_id,
            predicate,
            broadcast_msg,
            output.put_nowait,
            send,
            recv,
        ))
        rbc_msg = await output.get()
        self.output_queue.put_nowait((rec_id, dealer_id, rbc_msg))
        
    
    async def batch_robust_rec(self, rec_id, shares):
        self.global_num += 1

        sr = Serial(self.G1)
        serialized_shares = bytes(sr.serialize_fs(shares))


        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        async def predicate(_m):
            return True
        async def _setup(j):            

            rbctag = str(self.global_num) + str(rec_id) + ROBUSTRECMsgType.ROBUSTREC + str(j) # (M, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                rbc_input = serialized_shares
                print(f"my id: {self.my_id} rec_id: {rec_id}")                                  

            # rbc_outputs[j] = 
            
            rbc_task = asyncio.create_task(
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

            # await rbc_task

        await asyncio.gather(*[_setup(j) for j in range(1)])
        # await asyncio.gather(*[_setup(j) for j in range(self.n)])
        # rbc_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(self.n)))  
        rbc_list = await asyncio.gather(*(rbc_outputs[j].get() for j in range(1)))

        deserialized_rbc_list = [sr.deserialize_fs(item) for item in rbc_list]

        rbc_shares = [[None for _ in range(len(rbc_list))] for _ in range(len(deserialized_rbc_list[0]))]

        for i in range(len(deserialized_rbc_list[0])):
            for node in range(len(deserialized_rbc_list)):
                rbc_shares[i][node] = int(deserialized_rbc_list[node][i])

        GFEG1 = GF(Subgroup.BLS12_381)

        point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
        key_proposal = [i for i in range(self.n)]
        poly, err = [None] * len(rbc_shares), [None] * len(rbc_shares)
        for i in range(len(rbc_shares)): 
            poly[i], err[i] = await robust_reconstruct_admpc(rbc_shares[i], key_proposal, GFEG1, self.t, point, self.t)
        te = int(poly[0].coeffs[0])
        tes = self.ZR(te)
        err_list = [list(err[i]) for i in range(len(err))]

        for i in range(len(err_list)): 
            if len(err_list[i]) == 0: 
                continue
            else: 
                for j in range(len(err_list[i])): 
                    key_proposal.pop(err_list[i][j])


        rec_mvba_time = time.time()
        create_acs_task = asyncio.create_task(self.agreement_honeybadgermpc(key_proposal, rbc_shares, rec_id))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        rec_mvba_time = time.time() - rec_mvba_time
        print(f"rec_mvba_time: {rec_mvba_time}")
        mks, rec_values = output


        # self.output_queue.put_nowait(rec_value)
        return rec_values

    async def robust_rec_honeybadger(self, rbc_values, rbc_signal, rbc_shares, key_proposal):
        rec_await_rbc_signal_time = time.time()
        await rbc_signal.wait()
        rbc_signal.clear()
        rec_await_rbc_signal_time = time.time() - rec_await_rbc_signal_time
        print(f"rec_await_rbc_signal_time: {rec_await_rbc_signal_time}")

        
        # print(f"rbc_values: {rbc_values}")
        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        
        
        sc_shares = [] 
        for i in range(len(rbc_shares)): 
            sc_shares.append([])
            for j in range(len(self.mks)): 
                if key_proposal[j] in self.mks: 
                    sc_shares[i].append([key_proposal[j]+1, rbc_shares[i][j]])
            # for j in self.mks: 
            #     sc_shares[i].append([j+1, rbc_shares[i][j]])
        # for i in self.mks:
        #     sc_shares.append([i+1, rbc_shares[i]])
        res = [None] * len(rbc_shares)
        rec_sc_shares_time = time.time()
        for i in range(len(rbc_shares)): 
            res[i] = self.poly.interpolate_at(sc_shares[i], 0)
        # res = self.poly.interpolate_at(sc_shares, 0)
        # print(f"{self.my_id} res: {res}")
        rec_sc_shares_time = time.time() - rec_sc_shares_time
        print(f"rec_sc_shares_time: {rec_sc_shares_time}")
        return (self.mks, res)
        
    
    
    async def agreement_honeybadgermpc(self, key_proposal, rbc_shares, rec_id):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        
        coin_keys = [asyncio.Queue() for _ in range(self.n)]

        # print(f"my id: {self.my_id} rec_id: {rec_id}")

        async def predicate(_key_proposal):
            return True
            
            

        async def _setup(j):
            
            # starting RBC
            rbctag = str(self.global_num) + str(rec_id) + ROBUSTRECMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                # print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)  
                rbc_input = bytes(riv.array)
                # print(f"riv.array: {riv.array}")
                # print(f"rbc_input: {rbc_input}")

            # rbc_outputs[j] = 
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

            abatag = str(self.global_num) + str(rec_id) + ROBUSTRECMsgType.ABA + str(j) # (B, msg)
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
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.robust_rec_honeybadger(
                rbc_values,
                rbc_signal,
                rbc_shares,
                key_proposal
            ),
            work_tasks,
        )
