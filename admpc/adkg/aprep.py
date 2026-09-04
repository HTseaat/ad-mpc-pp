from adkg.polynomial import polynomials_over, EvalPoint
from adkg.utils.poly_misc import interpolate_g1_at_x
from adkg.utils.misc import wrap_send, subscribe_recv
import asyncio
import hashlib, time
from math import ceil
import logging
from adkg.utils.bitmap import Bitmap
from adkg.acss import ACSS, ACSS_Pre, ACSS_Foll

from adkg.broadcast.tylerba import tylerba
from adkg.broadcast.optqrbc import optqrbc, optqrbc_dynamic

from adkg.preprocessing import PreProcessedElements

from adkg.mpc import TaskProgramRunner
from adkg.utils.serilization import Serial
from adkg.rand import Rand, Rand_Pre, Rand_Foll, batchrand_batch_count
from adkg.robust_rec import Robust_Rec
import math

from adkg.field import GF, GFElement
from adkg.ntl import vandermonde_batch_evaluate
from adkg.elliptic_curve import Subgroup
from adkg.progs.mixins.dataflow import Share
from adkg.robust_reconstruction import robust_reconstruct_admpc, robust_rec_admpc

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)

class APREPMsgType:
    ACSS = "AP.A"
    RBC = "AP.R"
    ABA = "AP.B"
    PREKEY = "AP.P"
    KEY = "AP.K"
    MASK = "AP.M"
    GENRAND = "AP.GR"
    ROBUSTREC = "AP.RR"
    APREP = "AP.AP"
    
class APREP:
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix):
        self.public_keys, self.private_key, self.g, self.h = (public_keys, private_key, g, h)
        self.n, self.t, self.deg, self.my_id = (n, t, deg, my_id)
        self.sc = ceil((deg+1)/(t+1)) + 1
        self.send, self.recv, self.pc = (send, recv, pc)
        self.ZR, self.G1, self.multiexp, self.dotprod = curve_params
        self.matrix = matrix
        # print(f"type(self.ZR): {type(self.ZR)}")
        self.poly = polynomials_over(self.ZR)
        self.poly.clear_cache() #FIXME: Not sure why we need this.
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        rectag = APREPMsgType.ROBUSTREC
        recsend, recrecv = self.get_send(rectag), self.subscribe_recv(rectag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rec = Robust_Rec(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, recsend, recrecv, self.pc, curve_params)


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
            logging.info("APREP task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, outputs, aprep_values, acss_signal):
        
        acsstag = APREPMsgType.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, acsssend, acssrecv, self.pc, self.ZR, self.G1
                         )
        self.acss_tasks = [None] * self.n
        
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_aprep(0, values=aprep_values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss_aprep(0, dealer_id=i))

        while True:
            (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            
            if len(outputs) >= self.n - self.t:
                # print("Player " + str(self.my_id) + " Got shares from: " + str([output for output in outputs]))
                acss_signal.set()

            if len(outputs) == self.n:
                return    

    async def commonsubset(self, rbc_out, mult_triples_shares, rec_tau, cm, rbc_signal, rbc_values, coin_keys, aba_in, aba_out):
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
            # print(f"rbc_values[{j}]: {rbc_values[j]}")        
            
            if not aba_inputted[j]:
                aba_inputted[j] = True
                aba_in[j](1)
            
            subset = True
            while True:
                
                if subset:
                    coin_keys[j]((mult_triples_shares, rbc_values[j]))
                    return

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
    
    async def agreement(self, key_proposal, mult_triples_shares, rec_tau, cm):
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
                    for i in range(cm): 
                        if rec_tau[kk][i] != self.ZR(0): 
                            print(f"false")
                            subset = False
                    
                if subset:
                    return True
                

        async def _setup(j):
            
            # starting RBC
            rbctag =APREPMsgType.RBC + str(j) # (R, msg)
            rbcsend, rbcrecv = self.get_send(rbctag), self.subscribe_recv(rbctag)

            rbc_input = None
            if j == self.my_id: 
                # print(f"key_proposal: {key_proposal}")
                riv = Bitmap(self.n)
                for k in key_proposal: 
                    riv.set_bit(k)
                rbc_input = bytes(riv.array)


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

            abatag = APREPMsgType.ABA + str(j) # (B, msg)
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
                mult_triples_shares,
                rec_tau,
                cm,
                rbc_signal,
                rbc_values,
                [_.put_nowait for _ in coin_keys],
                [_.put_nowait for _ in aba_inputs],
                [_.get for _ in aba_outputs],
            ),
            self.new_triples(
                mult_triples_shares,
                cm,
                rbc_values,
                rbc_signal,
            ),
            work_tasks,
        )

    async def new_triples(self, mult_triples_shares, cm, rbc_values, rbc_signal):
        await rbc_signal.wait()
        rbc_signal.clear()


        self.mks = set() # master key set
        for ks in  rbc_values:
            if ks is not None:
                self.mks = self.mks.union(set(list(ks)))
                if len(self.mks) >= self.n-self.t:
                    break
        T_list = sorted(self.mks)

        # step 13
        u = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        v = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        w = [[self.ZR(0) for _ in range(2*self.t+1)] for _ in range(cm)]
        for i in range(cm): 
            for j in range(self.t+1): 
                index = T_list[j]
                u[i][j] = mult_triples_shares[index][i][0]
                v[i][j] = mult_triples_shares[index][i][1]
                w[i][j] = mult_triples_shares[index][i][2]
        
        u_poly, v_poly, w_poly = [], [], []
        for i in range(cm):
            u_poly.append([])
            v_poly.append([])
            # w_poly.append([])
            for j in range(self.t+1): 
                u_poly[i].append([T_list[j]+1, u[i][j]])
                v_poly[i].append([T_list[j]+1, v[i][j]])
            
        # step 14
        for i in range(cm):
            for j in range(self.t+1, 2*self.t+1): 
                index = T_list[j] + 1
                u[i][j] = self.poly.interpolate_at(u_poly[i], index)
                v[i][j] = self.poly.interpolate_at(v_poly[i], index)

        # step 15
        d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]  
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                d[i][j] = u[i][index1] - mult_triples_shares[index2][i][0]
                e[i][j] = v[i][index1] - mult_triples_shares[index2][i][1]
            

        # step 16
        d_list, e_list = [], []
        for i in range(cm): 
            d_list += d[i]
            e_list += e[i]
        rec_list = d_list + e_list
        # robust_rec = await self.robust_rec_step(rec_list, 3)
        rec_task3 = asyncio.create_task(self.rec_step(rec_list, 3))
        (mks, robust_rec) = await rec_task3
        # robust_rec_d = await self.robust_rec_step(d_list, robust_rec_sig)
  
        # robust_rec_e = await self.robust_rec_step(e_list, robust_rec_sig)
        robust_rec_d = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_e = robust_rec[int(len(robust_rec)/2):]
        
        rec_d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        rec_e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        for i in range(cm):
            for j in range(self.t): 
                rec_d[i][j] = robust_rec_d[i*self.t+j]
                rec_e[i][j] = robust_rec_e[i*self.t+j]

        # step 17    
        for i in range(cm):
            for j in range(self.t): 
                index1 = j + self.t + 1
                index2 = T_list[index1]
                w[i][index1] = rec_d[i][j] * rec_e[i][j] + rec_d[i][j] * mult_triples_shares[index2][i][1] + rec_e[i][j] * mult_triples_shares[index2][i][0] + mult_triples_shares[index2][i][2]

        # step 18
        for i in range(cm):
            w_poly.append([])
            for j in range(2*self.t+1): 
                w_poly[i].append([T_list[j]+1, w[i][j]])
        u_point, v_point, w_point = [None] * cm, [None] * cm, [None] * cm
        for i in range(cm):
            point = 3 * self.t + 2
            u_point[i] = self.poly.interpolate_at(u_poly[i], point)
            v_point[i] = self.poly.interpolate_at(v_poly[i], point)
            w_point[i] = self.poly.interpolate_at(w_poly[i], point)

        aprep_triples = []
        for i in range(cm): 
            aprep_triples.append([])
            aprep_triples[i].append(u_point[i])
            aprep_triples[i].append(v_point[i])
            aprep_triples[i].append(w_point[i])
            

        
        return aprep_triples
    
    
    async def gen_rand_step(self, rand_num, rand_outputs, rand_signal):
        
        if rand_num > self.n - self.t: 
            rounds = math.ceil(rand_num / (self. n - self.t))
        else: 
            rounds = 1
        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, curve_params, self.matrix)
        self.rand_task = asyncio.create_task(self.rand.run_rand(rand_num, rounds))

        while True: 
            # rand_outputs = await self.rand.output_queue.get()
            rand_outputs = await self.rand_task

            if len(rand_outputs) == rand_num: 
                # print(f"my id: {self.my_id} rand_outputs: {rand_outputs}")
                rand_signal.set()
                return rand_outputs
            
    async def robust_rec_step(self, rec_shares, index):                


        rec_values = await self.rec.batch_robust_rec(index, rec_shares)

        return rec_values
    
    async def rec_step(self, rec_shares, index):                
        

        self.rec_tasks = [None] * self.n
        
        for i in range(self.n):
            if i == self.my_id:
                self.rec_tasks[i] = asyncio.create_task(self.rec.run_robust_rec(index, values=rec_shares))
            else:
                self.rec_tasks[i] = asyncio.create_task(self.rec.run_robust_rec(index, dealer_id=i))

        outputs = []
        rbc_number = []
        while True:
            rec_id, dealer_id, rbc_msg = await self.rec.output_queue.get()
            if rec_id != index:
                continue
            outputs.append(rbc_msg)
            rbc_number.append(dealer_id)

            if len(outputs) == self.n:


                sr = Serial(self.G1)

                deserialized_rbc_list = [sr.deserialize_fs(item) for item in outputs]

                rbc_shares = [[None for _ in range(len(outputs))] for _ in range(len(deserialized_rbc_list[0]))]

                for i in range(len(deserialized_rbc_list[0])):
                    for node in range(len(deserialized_rbc_list)):
                        rbc_shares[i][node] = deserialized_rbc_list[node][i]



                GFEG1 = GF(Subgroup.BLS12_381)

                point = EvalPoint(GFEG1, self.n, use_omega_powers=False)
                key_proposal = rbc_number
                poly, err = [None] * len(rbc_shares), [None] * len(rbc_shares)
                rec_values = []
                for i in range(len(rbc_shares)): 
                    poly[i], err[i] = await robust_rec_admpc(rbc_shares[i], key_proposal, GFEG1, self.t, point, self.t)
                    constant = int(poly[i].coeffs[0])
                    rec_values.append(self.ZR(constant))
                te = int(poly[0].coeffs[0])
                tes = self.ZR(te)
                err_list = [list(err[i]) for i in range(len(err))]

                for i in range(len(err_list)): 
                    if len(err_list[i]) == 0: 
                        continue
                    else: 
                        for j in range(len(err_list[i])): 
                            key_proposal.pop(err_list[i][j])
                # print(f"my id: {self.my_id} key_proposal: {key_proposal}")

                return (key_proposal, rec_values)

                

            if len(outputs) == self.n:
                return 
        
   
    async def run_aprep(self, cm):
        run_aprep_start_time = time.time()
        gen_rand_outputs = []
        gen_rand_signal = asyncio.Event()

        # invoke Protocol Rand to generate random shares
        gen_rand_outputs = await self.gen_rand_step(self.n*cm, gen_rand_outputs, gen_rand_signal)
        

        acss_outputs = {}
        acss_signal = asyncio.Event()

        # Each participant generates the multiplication triples needed for the next epoch
        mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        # rand_values = [None] * cm
        for i in range(cm): 
            mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
            chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]

        aprep_values = (mult_triples, chec_triples, cm)      

        self.acss_task = asyncio.create_task(self.acss_step(acss_outputs, aprep_values, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()

        await gen_rand_signal.wait()
        gen_rand_signal.clear()

        # invoke Protocol Robust-Rec 
        # robust_rec_outputs = []
        rec_task = asyncio.create_task(self.rec_step(gen_rand_outputs, 0))
        (mks, robust_rec_outputs) = await rec_task
        mks_list = sorted(mks)


        mult_triples_shares = {}
        chec_triples_shares = {}
        rands = {}



        for node in mks_list:
            if node in acss_outputs:
                output = acss_outputs[node]

                mult_triples_shares[node] = [[self.ZR(0)] * 3 for _ in range(cm)]
                chec_triples_shares[node] = [[self.ZR(0)] * 3 for _ in range(cm)]
                rands[node] = [self.ZR(0)] * cm

                msg_flat = output['shares']['msg'][0]        # 6*cm

                for i in range(cm):
                    mult_start = 3 * i
                    chec_start = 3 * (cm + i)

                    mult_triples_shares[node][i] = msg_flat[mult_start:mult_start + 3]
                    chec_triples_shares[node][i] = msg_flat[chec_start:chec_start + 3]

                    rands[node][i] = robust_rec_outputs[node * cm + i]


            else:
                print(f"Warning: Node {node} is not present in acss_outputs")




        rho = {node: [0] * cm for node in mult_triples_shares}
        sigma = {node: [0] * cm for node in mult_triples_shares}

        for node, outputs in mult_triples_shares.items():
            for i in range(cm):
                rho[node][i] = rands[node][i] * mult_triples_shares[node][i][0] - chec_triples_shares[node][i][0]
                sigma[node][i] = mult_triples_shares[node][i][1] - chec_triples_shares[node][i][1]

        rho_list = []
        sigma_list = []
        for node in mult_triples_shares:
            rho_list += rho[node]
            sigma_list += sigma[node]

        # invoke Robust-Rec to rec rho and sigma
        aprep_rec_start_time = time.time()
        rec_list = rho_list + sigma_list

        # execute Robust-Rec
        rec_task1 = asyncio.create_task(self.rec_step(rec_list, 1))
        (mks, robust_rec) = await rec_task1
        mks_list = sorted(mks)
        

        robust_rec_rho = robust_rec[:int(len(robust_rec)/2)]
        robust_rec_sigma = robust_rec[int(len(robust_rec)/2):]

        rec_rho   = {node: [self.ZR(0)] * cm for node in mult_triples_shares}
        rec_sigma = {node: [self.ZR(0)] * cm for node in mult_triples_shares}
        tau       = {node: [self.ZR(0)] * cm for node in mult_triples_shares}

        for node, outputs in mult_triples_shares.items():
            if node in mks_list: 
                for i in range(cm):
                    index = mks_list.index(node)
                    rec_rho[node][i] = robust_rec_rho[index * cm + i]
                    rec_sigma[node][i] = robust_rec_sigma[index * cm + i]


        for node, outputs in mult_triples_shares.items():
            for i in range(cm):
                tau[node][i] = (rands[node][i] * mult_triples_shares[node][i][2] - chec_triples_shares[node][i][2] -
                                rec_sigma[node][i] * chec_triples_shares[node][i][0] - rec_rho[node][i] * chec_triples_shares[node][i][1] -
                                rec_rho[node][i] * rec_sigma[node][i])
                
        tau_list = []
        for node in mult_triples_shares:
            tau_list += tau[node]

        rec_task2 = asyncio.create_task(self.rec_step(tau_list, 2))
        (mks, robust_rec_tau) = await rec_task2
        mks_list = sorted(mks)

        rec_tau = {node: [0] * cm for node in mult_triples_shares}
        for node, outputs in mult_triples_shares.items():
            if node in mks_list: 
                for i in range(cm):
                    index = mks_list.index(node)
                    rec_tau[node][i] = robust_rec_tau[index * cm + i]

                    
        key_proposal = []
        for node, values in rec_tau.items():
            add_node = True  
            for value in values:
                if value != self.ZR(0):
                    add_node = False  
                    break
            if add_node:
                key_proposal.append(node)

        

        # MVBA
        create_acs_task = asyncio.create_task(self.agreement(key_proposal, mult_triples_shares, rec_tau, cm))
        acs, key_task, work_tasks = await create_acs_task
        await acs
        output = await key_task
        await asyncio.gather(*work_tasks)
        # mks, sk, pk = output
        new_mult_triples = output

        duration = time.time() - run_aprep_start_time
        print(f"my id: {self.my_id} APREP protocol total time: {duration:.4f} seconds")

        # self.output_queue.put_nowait(new_mult_triples)
        return new_mult_triples
        
class APREP_Pre(APREP):
    def __init__(self, public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        
        self.mpc_instance = mpc_instance

        super().__init__(public_keys, private_key, g, h, n, t, deg, my_id, send, recv, pc, curve_params, matrix)
            
    def kill(self):
        self.subscribe_recv_task.cancel()
        for name in ("acss_task", "rand_task", "rand_setup_task"):
            task = getattr(self, name, None)
            if task is not None:
                task.cancel()
        acss = getattr(self, "acss", None)
        if acss is not None:
            acss.kill()
        rand = getattr(self, "rand", None)
        if rand is not None:
            rand.kill()
        self.rec.kill()
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, aprep_values):

        
        admpc_control_instance = self.mpc_instance.admpc_control_instance
        layerID = self.mpc_instance.layer_ID
        pks_next_layer = admpc_control_instance.pks_all[layerID + 1]       

        
        acsstag = APREPMsgType.ACSS + str(layerID) + str(self.my_id)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS_Pre(pks_next_layer,
                             self.g, self.h, self.n, self.t, self.deg, self.sc, self.my_id, 
                             acsssend, acssrecv, self.pc, self.ZR, self.G1, 
                             mpc_instance=self.mpc_instance
                         )
        self.acss.metrics_protocol = "adprep"
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss_aprep(0, values=aprep_values))

    
    async def gen_rand_step(self, rand_num):
        rounds = batchrand_batch_count(rand_num, self.t)
        randtag = APREPMsgType.GENRAND
        randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand = Rand_Pre(self.public_keys, self.private_key, 
                             self.g, self.h, self.n, self.t, self.deg, self.my_id, 
                             randsend, randrecv, self.pc, curve_params, self.matrix, 
                             mpc_instance=self.mpc_instance)
        self.rand.metrics_protocol = "adprep_rand"
        self.rand_task = asyncio.create_task(self.rand.run_rand(rand_num, rounds))
   
    async def run_aprep(self, cm):
        if not isinstance(cm, int) or cm < 0:
            raise ValueError("ADprep cm must be a non-negative integer")
        if cm == 0:
            return
        mult_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        chec_triples = [[self.ZR.rand() for _ in range(3)] for _ in range(cm)]
        for i in range(cm): 
            mult_triples[i][2] = mult_triples[i][0] * mult_triples[i][1]
            chec_triples[i][2] = chec_triples[i][0] * chec_triples[i][1]

        aprep_values = (mult_triples, chec_triples, cm)      
        # Algorithm 2 needs one challenge r_i per dealer, not one challenge
        # per (dealer, triple) pair.  Start BACSS and BatchRand concurrently.
        self.rand_setup_task = asyncio.create_task(
            self.gen_rand_step(self.n)
        )
        await self.rand_setup_task
        self.acss_task = asyncio.create_task(
            self.acss_step(aprep_values)
        )

        
    
class APREP_Foll(APREP):
    PENDING_BACSS = "PENDING_BACSS"
    BACSS_READY = "BACSS_READY"
    SACRIFICE_PENDING = "SACRIFICE_PENDING"
    VALID = "VALID"
    INVALID = "INVALID"

    def __init__(self, public_keys, private_key, g, h, n, t, deg,
                 my_id, send, recv, pc, curve_params, matrix, mpc_instance):
        self.mpc_instance = mpc_instance
        super().__init__(
            public_keys, private_key, g, h, n, t, deg, my_id,
            send, recv, pc, curve_params, matrix,
        )
        if self.n != 3 * self.t + 1:
            raise ValueError("ADprep requires the paper parameter n=3*t+1")
        self.quorum_size = self.n - self.t
        self.aprep_session = 0
        self.acss_instances = []
        self.validation_tasks = []
        self.rbc_tasks = []
        self.agreement_work_tasks = []

    def kill(self):
        self.subscribe_recv_task.cancel()
        for collection_name in (
            "acss_tasks", "validation_tasks", "rbc_tasks",
            "agreement_work_tasks",
        ):
            for task in getattr(self, collection_name, ()):
                if task is not None:
                    task.cancel()
        for task_name in (
            "acss_task", "rand_task", "rand_setup_task",
            "validation_watcher",
        ):
            task = getattr(self, task_name, None)
            if task is not None:
                task.cancel()
        for acss in getattr(self, "acss_instances", ()):
            if acss is None:
                continue
            try:
                acss.kill()
            except Exception:
                logger.debug(
                    "ADprep BACSS instance already stopped", exc_info=True
                )
        rand_foll = getattr(self, "rand_foll", None)
        if rand_foll is not None:
            rand_foll.kill()
        self.rec.kill()
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    async def acss_step(self, cm, outputs, dealer_states,
                        bacss_decided, dealer_decided):
        self.acss_tasks = [None] * self.n
        self.acss_instances = [None] * self.n

        async def _run_dealer(dealer_id, acss):
            try:
                result = await acss.avss_aprep(0, dealer_id, cm)
                if result[0] != dealer_id:
                    raise ValueError(
                        "ADprep BACSS returned dealer %s for task %s"
                        % (result[0], dealer_id)
                    )
                return dealer_id, result, None
            except asyncio.CancelledError:
                raise
            except Exception as exception:
                return dealer_id, None, exception

        for dealer_id in range(self.n):
            acsstag = (
                APREPMsgType.ACSS
                + str(self.mpc_instance.layer_ID - 1)
                + str(dealer_id)
            )
            acsssend = self.get_send(acsstag)
            acssrecv = self.subscribe_recv(acsstag)
            acss = ACSS_Foll(
                self.public_keys, self.private_key, self.g, self.h,
                self.n, self.t, self.deg, self.sc, self.my_id,
                acsssend, acssrecv, self.pc, self.ZR, self.G1,
                mpc_instance=self.mpc_instance,
            )
            acss.metrics_protocol = "adprep"
            self.acss = acss
            self.acss_instances[dealer_id] = acss
            self.acss_tasks[dealer_id] = asyncio.create_task(
                _run_dealer(dealer_id, acss)
            )

        for completed in asyncio.as_completed(self.acss_tasks):
            dealer, result, error = await completed
            if error is not None:
                logger.warning(
                    "[%d] ADprep rejected BACSS dealer %d: %s",
                    self.my_id, dealer, error,
                )
                dealer_states[dealer] = self.INVALID
                bacss_decided[dealer].set()
                dealer_decided[dealer].set()
                continue

            _, _, shares, commitments = result
            outputs[dealer] = {
                "shares": shares,
                "commits": commitments,
            }
            dealer_states[dealer] = self.BACSS_READY
            bacss_decided[dealer].set()

    def _encode_proposal(self, proposal):
        proposal = tuple(int(dealer) for dealer in proposal)
        if (
            len(proposal) != self.quorum_size
            or len(set(proposal)) != self.quorum_size
            or any(dealer < 0 or dealer >= self.n for dealer in proposal)
        ):
            raise ValueError(
                "ADprep proposal must contain exactly "
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

    async def _proposal_is_valid(self, encoded, dealer_states,
                                 dealer_decided):
        proposal = self._decode_proposal(encoded)
        if proposal is None:
            return False
        await asyncio.gather(*(
            dealer_decided[dealer].wait() for dealer in proposal
        ))
        return all(
            dealer_states[dealer] == self.VALID
            for dealer in proposal
        )

    def _decode_dealer_triples(self, dealer, output, cm):
        try:
            rows = output["shares"]["msg"]
            if len(rows) != 1:
                raise ValueError(f"expected one share row, got {len(rows)}")
            flat = list(rows[0])
        except (KeyError, TypeError, IndexError) as exception:
            raise ValueError(
                f"ADprep dealer {dealer} returned malformed shares"
            ) from exception
        expected = 6 * cm
        if len(flat) != expected:
            raise ValueError(
                f"ADprep dealer {dealer} returned {len(flat)} shares, "
                f"expected {expected}"
            )
        main = [
            flat[3 * index:3 * index + 3]
            for index in range(cm)
        ]
        check_offset = 3 * cm
        sacrificed = [
            flat[check_offset + 3 * index:check_offset + 3 * index + 3]
            for index in range(cm)
        ]
        return main, sacrificed

    def _robust_instance_id(self, phase, dealer=None):
        dealer_part = "common" if dealer is None else f"dealer-{dealer}"
        return (
            f"adprep-session-{self.aprep_session}:"
            f"{dealer_part}:phase-{phase}"
        )

    async def robust_rec_step(self, rec_shares, phase, dealer=None):
        return await self.rec.batch_run_robust_rec(
            phase,
            rec_shares,
            self.member_list,
            instance_id=self._robust_instance_id(phase, dealer),
        )

    async def _validate_dealer(
            self, dealer, cm, rand_outputs, acss_outputs,
            dealer_states, bacss_decided, dealer_decided,
            mult_triples_shares, rec_tau, valid_dealers,
            quorum_proposal):
        await bacss_decided[dealer].wait()
        if dealer_states[dealer] != self.BACSS_READY:
            return

        dealer_states[dealer] = self.SACRIFICE_PENDING
        try:
            main, sacrificed = self._decode_dealer_triples(
                dealer, acss_outputs[dealer], cm
            )

            # Algorithm 2 line 205: r_i is opened only after this dealer's
            # BACSS instance has become locally valid.
            random_value = (
                await self.robust_rec_step(
                    [rand_outputs[dealer]], "random", dealer
                )
            )[0]

            rho = [
                random_value * main[index][0] - sacrificed[index][0]
                for index in range(cm)
            ]
            sigma = [
                main[index][1] - sacrificed[index][1]
                for index in range(cm)
            ]
            opened = await self.robust_rec_step(
                rho + sigma, "rho-sigma", dealer
            )
            if len(opened) != 2 * cm:
                raise RuntimeError(
                    f"ADprep dealer {dealer} rho/sigma reconstruction "
                    "returned an incomplete batch"
                )
            opened_rho = opened[:cm]
            opened_sigma = opened[cm:]

            tau_shares = []
            for index in range(cm):
                tau_shares.append(
                    random_value * main[index][2]
                    - sacrificed[index][2]
                    - opened_sigma[index] * sacrificed[index][0]
                    - opened_rho[index] * sacrificed[index][1]
                    - opened_rho[index] * opened_sigma[index]
                )
            opened_tau = await self.robust_rec_step(
                tau_shares, "tau", dealer
            )
            if len(opened_tau) != cm:
                raise RuntimeError(
                    f"ADprep dealer {dealer} tau reconstruction returned "
                    "an incomplete batch"
                )
            rec_tau[dealer] = list(opened_tau)

            if not all(value == self.ZR(0) for value in opened_tau):
                dealer_states[dealer] = self.INVALID
                logger.warning(
                    "[%d] ADprep sacrifice rejected dealer %d: nonzero tau",
                    self.my_id, dealer,
                )
                return

            mult_triples_shares[dealer] = main
            valid_dealers.add(dealer)
            dealer_states[dealer] = self.VALID
            if (
                len(valid_dealers) >= self.quorum_size
                and not quorum_proposal.done()
            ):
                quorum_proposal.set_result(tuple(
                    sorted(valid_dealers)[:self.quorum_size]
                ))
        except asyncio.CancelledError:
            raise
        except Exception as exception:
            dealer_states[dealer] = self.INVALID
            logger.warning(
                "[%d] ADprep sacrifice failed for dealer %d: %s",
                self.my_id, dealer, exception,
            )
        finally:
            dealer_decided[dealer].set()
          

    async def commonsubset(
            self, rbc_out, mult_triples_shares, dealer_states,
            dealer_decided, rbc_signal, rbc_values, coin_keys,
            aba_in, aba_out):
        assert len(rbc_out) == self.n
        assert len(aba_in) == self.n
        assert len(aba_out) == self.n

        aba_inputted = [False] * self.n
        aba_values = [0] * self.n

        async def _recv_rbc(proposer):
            encoded = await rbc_out[proposer].get()
            proposal = self._decode_proposal(encoded)
            if proposal is None:
                raise ValueError("RBC returned an invalid ADprep proposal")
            await asyncio.gather(*(
                dealer_decided[dealer].wait() for dealer in proposal
            ))
            if not all(
                dealer_states[dealer] == self.VALID
                and dealer in mult_triples_shares
                for dealer in proposal
            ):
                raise RuntimeError(
                    "ADprep RBC output referenced a locally invalid dealer"
                )
            rbc_values[proposer] = list(proposal)
            if not aba_inputted[proposer]:
                aba_inputted[proposer] = True
                aba_in[proposer](1)
            coin_keys[proposer]((mult_triples_shares, list(proposal)))

        r_threads = [
            asyncio.create_task(_recv_rbc(proposer))
            for proposer in range(self.n)
        ]

        async def _recv_aba(proposer):
            aba_values[proposer] = await aba_out[proposer]()

            if sum(aba_values) >= 1:
                for other in range(self.n):
                    if not aba_inputted[other]:
                        aba_inputted[other] = True
                        aba_in[other](0)

        await asyncio.gather(*[
            asyncio.create_task(_recv_aba(proposer))
            for proposer in range(self.n)
        ])
        if sum(aba_values) < 1:
            raise RuntimeError("ADprep agreement accepted no proposal")

        cancelled = []
        for proposer in range(self.n):
            if aba_values[proposer]:
                await r_threads[proposer]
                if rbc_values[proposer] is None:
                    raise RuntimeError(
                        "ADprep ABA accepted a missing RBC proposal"
                    )
            else:
                r_threads[proposer].cancel()
                cancelled.append(r_threads[proposer])
                rbc_values[proposer] = None
        if cancelled:
            await asyncio.gather(*cancelled, return_exceptions=True)
        rbc_signal.set()
    
    async def agreement(
            self, key_proposal, mult_triples_shares,
            dealer_states, dealer_decided, cm):
        aba_inputs = [asyncio.Queue() for _ in range(self.n)]
        aba_outputs = [asyncio.Queue() for _ in range(self.n)]
        rbc_outputs = [asyncio.Queue() for _ in range(self.n)]
        coin_keys = [asyncio.Queue() for _ in range(self.n)]
        local_rbc_input = self._encode_proposal(key_proposal)

        async def predicate(encoded):
            return await self._proposal_is_valid(
                encoded, dealer_states, dealer_decided
            )

        async def _setup(proposer):
            rbctag = (
                f"{APREPMsgType.RBC}{self.aprep_session}:"
                f"proposer-{proposer}"
            )
            rbcsend = self.get_send(rbctag)
            rbcrecv = self.subscribe_recv(rbctag)
            rbc_input = (
                local_rbc_input if proposer == self.my_id else None
            )
            self.rbc_tasks[proposer] = asyncio.create_task(
                optqrbc_dynamic(
                    rbctag,
                    self.my_id,
                    self.n,
                    self.t,
                    proposer,
                    predicate,
                    rbc_input,
                    rbc_outputs[proposer].put_nowait,
                    rbcsend,
                    rbcrecv,
                    self.member_list,
                )
            )

            abatag = (
                f"{APREPMsgType.ABA}{self.aprep_session}:"
                f"proposer-{proposer}"
            )
            abasend = self.get_send(abatag)
            abarecv = self.subscribe_recv(abatag)

            def bcast(message):
                for member in self.member_list:
                    abasend(member, message)

            return asyncio.create_task(
                tylerba(
                    abatag,
                    self.my_id,
                    self.n,
                    self.t,
                    coin_keys[proposer].get,
                    aba_inputs[proposer].get,
                    aba_outputs[proposer].put_nowait,
                    bcast,
                    abarecv,
                )
            )

        self.rbc_tasks = [None] * self.n
        self.agreement_work_tasks = await asyncio.gather(*[
            _setup(proposer) for proposer in range(self.n)
        ])
        rbc_signal = asyncio.Event()
        rbc_values = [None] * self.n

        return (
            self.commonsubset(
                rbc_outputs,
                mult_triples_shares,
                dealer_states,
                dealer_decided,
                rbc_signal,
                rbc_values,
                [queue.put_nowait for queue in coin_keys],
                [queue.put_nowait for queue in aba_inputs],
                [queue.get for queue in aba_outputs],
            ),
            self.new_triples(
                mult_triples_shares, cm, rbc_values, rbc_signal
            ),
            self.agreement_work_tasks,
        )

    def _select_common_set(self, rbc_values):
        for proposal in rbc_values:
            if proposal is None:
                continue
            common_set = tuple(proposal)
            try:
                self._encode_proposal(common_set)
            except ValueError as exception:
                raise RuntimeError(
                    "Agreed ADprep proposal is not an exact valid quorum"
                ) from exception
            return common_set
        raise RuntimeError("ADprep agreement returned no accepted proposal")

    async def new_triples(self, mult_triples_shares, cm,
                          rbc_values, rbc_signal):
        await rbc_signal.wait()
        common_set = self._select_common_set(rbc_values)
        if not all(
            dealer in mult_triples_shares for dealer in common_set
        ):
            raise RuntimeError(
                "ADprep common set contains a dealer without valid triples"
            )
        self.common_subset = common_set
        self.mks = set(common_set)

        domain_size = 2 * self.t + 1
        u = [[self.ZR(0) for _ in range(domain_size)] for _ in range(cm)]
        v = [[self.ZR(0) for _ in range(domain_size)] for _ in range(cm)]
        w = [[self.ZR(0) for _ in range(domain_size)] for _ in range(cm)]

        # Relabel the exact MVBA output by positions 1..2t+1 as in
        # Algorithm 2; sparse dealer IDs are not interpolation coordinates.
        for triple_index in range(cm):
            for position in range(self.t + 1):
                dealer = common_set[position]
                triple = mult_triples_shares[dealer][triple_index]
                u[triple_index][position] = triple[0]
                v[triple_index][position] = triple[1]
                w[triple_index][position] = triple[2]

        u_poly = []
        v_poly = []
        for triple_index in range(cm):
            u_poly.append([
                [position + 1, u[triple_index][position]]
                for position in range(self.t + 1)
            ])
            v_poly.append([
                [position + 1, v[triple_index][position]]
                for position in range(self.t + 1)
            ])
            for position in range(self.t + 1, domain_size):
                evaluation_point = position + 1
                u[triple_index][position] = self.poly.interpolate_at(
                    u_poly[triple_index], evaluation_point
                )
                v[triple_index][position] = self.poly.interpolate_at(
                    v_poly[triple_index], evaluation_point
                )

        d = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        e = [[self.ZR(0) for _ in range(self.t)] for _ in range(cm)]
        for triple_index in range(cm):
            for offset in range(self.t):
                position = self.t + 1 + offset
                dealer = common_set[position]
                triple = mult_triples_shares[dealer][triple_index]
                d[triple_index][offset] = (
                    u[triple_index][position] - triple[0]
                )
                e[triple_index][offset] = (
                    v[triple_index][position] - triple[1]
                )

        rec_list = [
            value for row in d for value in row
        ] + [
            value for row in e for value in row
        ]
        opened = await self.robust_rec_step(rec_list, "extract-mul")
        half = len(opened) // 2
        opened_d = opened[:half]
        opened_e = opened[half:]
        if len(opened_d) != cm * self.t or len(opened_e) != cm * self.t:
            raise RuntimeError(
                "ADprep extraction multiplication returned an incomplete batch"
            )

        for triple_index in range(cm):
            for offset in range(self.t):
                position = self.t + 1 + offset
                dealer = common_set[position]
                triple = mult_triples_shares[dealer][triple_index]
                opened_d_value = opened_d[triple_index * self.t + offset]
                opened_e_value = opened_e[triple_index * self.t + offset]
                w[triple_index][position] = (
                    opened_d_value * opened_e_value
                    + opened_d_value * triple[1]
                    + opened_e_value * triple[0]
                    + triple[2]
                )

        beta = 3 * self.t + 2
        triples = []
        for triple_index in range(cm):
            w_poly = [
                [position + 1, w[triple_index][position]]
                for position in range(domain_size)
            ]
            triples.append([
                self.poly.interpolate_at(u_poly[triple_index], beta),
                self.poly.interpolate_at(v_poly[triple_index], beta),
                self.poly.interpolate_at(w_poly, beta),
            ])
        return triples
    
    
    async def gen_rand_step(self, rand_num):
        rounds = batchrand_batch_count(rand_num, self.t)

        randtag = APREPMsgType.GENRAND
        randsend = self.get_send(randtag)
        randrecv = self.subscribe_recv(randtag)
        curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        self.rand_foll = Rand_Foll(
            self.public_keys, self.private_key, self.g, self.h,
            self.n, self.t, self.deg, self.my_id, randsend, randrecv,
            self.pc, curve_params, self.matrix,
            mpc_instance=self.mpc_instance,
        )
        self.rand_foll.metrics_protocol = "adprep_rand"
        self.rand_task = asyncio.create_task(
            self.rand_foll.run_rand(rand_num, rounds)
        )
        return await self.rand_task
        
    
    async def run_aprep(self, cm):
        if not isinstance(cm, int) or cm < 0:
            raise ValueError("ADprep cm must be a non-negative integer")
        if cm == 0:
            return []
        print(f"aprep_foll run_aprep cm: {cm}")
        self.aprep_session += 1
        self.member_list = [
            self.n * self.mpc_instance.layer_ID + local_id
            for local_id in range(self.n)
        ]

        acss_outputs = {}
        mult_triples_shares = {}
        rec_tau = {}
        valid_dealers = set()
        dealer_states = [self.PENDING_BACSS] * self.n
        bacss_decided = [asyncio.Event() for _ in range(self.n)]
        dealer_decided = [asyncio.Event() for _ in range(self.n)]
        quorum_proposal = asyncio.get_running_loop().create_future()

        self.dealer_states = dealer_states
        self.dealer_decided = dealer_decided
        self.valid_dealers = valid_dealers
        self.rec_tau = rec_tau
        self.mult_triples_shares = mult_triples_shares

        # BACSS and BatchRand run concurrently.  Sacrifice starts only after
        # BatchRand is ready and then waits independently for BACSS_i.
        self.acss_task = asyncio.create_task(self.acss_step(
            cm,
            acss_outputs,
            dealer_states,
            bacss_decided,
            dealer_decided,
        ))
        self.rand_setup_task = asyncio.create_task(
            self.gen_rand_step(self.n)
        )
        rand_outputs = await self.rand_setup_task
        if len(rand_outputs) != self.n:
            raise RuntimeError(
                f"ADprep BatchRand returned {len(rand_outputs)} shares, "
                f"expected n={self.n}"
            )
        self.rand_outputs = list(rand_outputs)

        self.validation_tasks = [
            asyncio.create_task(self._validate_dealer(
                dealer,
                cm,
                self.rand_outputs,
                acss_outputs,
                dealer_states,
                bacss_decided,
                dealer_decided,
                mult_triples_shares,
                rec_tau,
                valid_dealers,
                quorum_proposal,
            ))
            for dealer in range(self.n)
        ]

        async def _watch_validation_exhaustion():
            await asyncio.gather(
                *self.validation_tasks, return_exceptions=True
            )
            if not quorum_proposal.done():
                quorum_proposal.set_exception(RuntimeError(
                    "ADprep exhausted all dealer validations before "
                    f"collecting n-t={self.quorum_size} valid dealers"
                ))

        self.validation_watcher = asyncio.create_task(
            _watch_validation_exhaustion()
        )
        key_proposal = list(await quorum_proposal)

        acs, key_task, work_tasks = await self.agreement(
            key_proposal,
            mult_triples_shares,
            dealer_states,
            dealer_decided,
            cm,
        )
        await acs
        new_mult_triples = await key_task
        await asyncio.gather(*work_tasks)
        return new_mult_triples
