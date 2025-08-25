# from beaver.polynomial import polynomials_over
# from beaver.utils.poly_misc import interpolate_g1_at_x
from beaver.utils.misc import wrap_send, subscribe_recv
import json
import asyncio
import hashlib, time
from math import ceil
import logging
from beaver.utils.bitmap import Bitmap
from beaver.hbacss import Hbacss0, ACSS_Pre, ACSS_Foll
from beaver.transfer import DynamicTransfer, Transfer_Pre, Transfer_Foll
from beaver.batch_multiplication import BatchMultiplication, BatchMul_Pre, BatchMul_Foll
# from beaver.router import SimpleRouter

from beaver.broadcast.tylerba import tylerba
from beaver.broadcast.optqrbc import optqrbc


import math

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.NOTSET)
# Configure root logger to output INFO level messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s [%(name)s] %(message)s')

from ctypes import c_int, c_char_p, CDLL
lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype  = c_char_p
lib.pyCommit.argtypes  = [c_char_p, c_char_p, c_int]   # (Pk, values, t)
lib.pyCommit.restype   = c_char_p
# Bind the circuit addition function from Go
lib.pyCircuitAdd.argtypes = [c_char_p, c_char_p]
lib.pyCircuitAdd.restype  = c_char_p

class ADMPCMsgType:
    ACSS = "A"
    RBC = "R"
    ABA = "B"
    PREKEY = "P"
    KEY = "K"
    GENRAND = "GR"
    ROBUSTREC = "RR"
    TRANS = "TR"
    APREP = "AP"
    MUL = "M"
    

class ADMPC:
    def __init__(self, public_keys, private_key, pkbls, skbls, n, t, srs, my_id, send, recv, next_pks=None):
        self.public_keys, self.private_key, self.pkbls, self.skbls = (public_keys, private_key, pkbls, skbls)
        self.n, self.t, self.deg, self.my_id = (n, t, t, my_id)
        self.srs = srs
        self.send, self.recv = (send, recv)
        self.next_pks = next_pks
        
        
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        # rectag = ADMPCMsgType.ROBUSTREC
        # recsend, recrecv = self.get_send(rectag), self.subscribe_recv(rectag)
        # curve_params = (self.ZR, self.G1, self.multiexp, self.dotprod)
        # self.rec = Robust_Rec(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, recsend, recrecv, self.pc, curve_params)




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
            logging.info("ADMPC task finished")
        

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self
    
    
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
            if len(outputs) == self.n - 1: 

                sr = Serial(self.G1)

                # First, deserialize the entire rbc_list
                deserialized_rbc_list = [sr.deserialize_fs(item) for item in outputs]


                # Initialize the rbc_shares 2D list
                rbc_shares = [[None for _ in range(len(outputs))] for _ in range(len(deserialized_rbc_list[0]))]

                # Populate the rbc_shares 2D list
                for i in range(len(deserialized_rbc_list[0])):
                    for node in range(len(deserialized_rbc_list)):
                        rbc_shares[i][node] = int(deserialized_rbc_list[node][i])



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

                return (key_proposal, rec_values)

                
            if len(outputs) == self.n:
                return 
        
   
    
    async def mult(self, mult_values, mult_triples, layer): 
        gamma_list, epsilon_list = [None] * len(mult_values), [None] * len(mult_values)
        
        if layer == 200: 
            batch_rec_list = []

            byzantine_nodes = [1]
            for i in range(len(mult_values)): 
                if self.my_id in byzantine_nodes: 
                    gamma_list[i] = self.ZR(0)
                    epsilon_list[i] = self.ZR(0)
                    batch_rec_list.append(gamma_list[i])
                    batch_rec_list.append(epsilon_list[i])
                else: 
                    gamma_list[i] = mult_values[i][0] - mult_triples[layer*self.cm+i][0]
                    epsilon_list[i] = mult_values[i][1] - mult_triples[layer*self.cm+i][1]
                    batch_rec_list.append(gamma_list[i])
                    batch_rec_list.append(epsilon_list[i])

            rec_task = asyncio.create_task(self.rec_step(batch_rec_list, layer))
            (mks, rec_values) = await rec_task
            num = 0
            rec_gamma_list, rec_epsilon_list = [], []
            for i in range(len(mult_values)):
                rec_gamma_list.append(rec_values[num])
                rec_epsilon_list.append(rec_values[num+1])
                num += 2
            mult_outputs = [None] * len(mult_values)
            for i in range(len(mult_values)):
                mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]

        else: 
            batch_rec_list = []
            for i in range(len(mult_values)): 
                gamma_list[i] = mult_values[i][0] - mult_triples[layer*self.cm+i][0]
                epsilon_list[i] = mult_values[i][1] - mult_triples[layer*self.cm+i][1]
                batch_rec_list.append(gamma_list[i])
                batch_rec_list.append(epsilon_list[i])

            rec_task = asyncio.create_task(self.rec_step(batch_rec_list, layer))
            (mks, rec_values) = await rec_task
            num = 0
            rec_gamma_list, rec_epsilon_list = [], []
            for i in range(len(mult_values)):
                rec_gamma_list.append(rec_values[num])
                rec_epsilon_list.append(rec_values[num+1])
                num += 2
            mult_outputs = [None] * len(mult_values)
            for i in range(len(mult_values)):
                mult_outputs[i] = mult_triples[i][2] + rec_gamma_list[i] * mult_triples[i][1] + rec_epsilon_list[i] * mult_triples[i][0] + rec_gamma_list[i] * rec_epsilon_list[i]


        return mult_outputs

    
    async def run_computation(self, inputs, gate_tape, mult_triples, layer):
        print(f"len inputs: {len(inputs)} len gate_tape: {len(gate_tape)} len mult: {len(mult_triples)}")

        
        self.gates_num = len(gate_tape)
        # 这里根据当前层门的数量对输入进行划分
        gate_input_values = [[self.ZR(0) for _ in range(2)] for _ in range(self.gates_num)]
        for i in range(self.gates_num): 
            for j in range(2): 
                gate_input_values[i][j] = inputs[j]
        # 输出存在这里
        gate_output_values = [None] * self.gates_num
        # 这两个用来记录当前层的乘法门位置和数量，用来做当前层乘法门的批处理
        batch_mult_gates, mult_pos = [], []
        triple_num = 0
        for i in range(self.gates_num): 
            # 这是加法
            if gate_tape[i] == 0: 
                gate_output_values[i] = gate_input_values[i][0] + gate_input_values[i][1]
            # 这是乘法
            else: 
                batch_mult_gates.append(gate_input_values[i])
                mult_pos.append(i)
                # gate_output_values[i] = await self.mult(gate_input_values[i], mult_triples[triple_num])
                # triple_num += 1

        batch_mult_outputs = await self.mult(batch_mult_gates, mult_triples, layer)
        for i in range(len(mult_pos)): 
            gate_output_values[mult_pos[i]] = batch_mult_outputs[i]

        # self.output_queue.put_nowait(gate_output_values)
        return gate_output_values
    
   
    async def run_admpc(self, start_time):
        layers = self.layers
        self.cm = int(self.total_cm / layers)
        cm = self.cm
        w = 2 * cm
        print(f"cm: {cm} layers: {layers}")

        if self.my_id != 200:
            step3_start_time = time.time()
            apreptag = ADMPCMsgType.APREP
            aprepsend, apreprecv = self.get_send(apreptag), self.subscribe_recv(apreptag)
            aprep = APREP(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, aprepsend, apreprecv, self.pc, self.curve_params, self.matrix)
            new_mult_triples = await aprep.run_aprep(self.total_cm)
            step3_time = time.time() - step3_start_time

            print(f"prepare mult_triples time: {step3_time}")
            
            intput_num = 2 * w

            if intput_num > self.n - self.t: 
                rounds = math.ceil(intput_num / (self.n - self.t))
            else: 
                rounds = 1

            step2_start_time = time.time()
            randtag = ADMPCMsgType.GENRAND
            randsend, randrecv = self.get_send(randtag), self.subscribe_recv(randtag)
            rand = Rand(self.public_keys, self.private_key, self.g, self.h, self.n, self.t, self.deg, self.my_id, randsend, randrecv, self.pc, self.curve_params, self.matrix)
            new_shares = await rand.run_rand(intput_num, rounds)
            step2_time = time.time() - step2_start_time
            print(f"prepare new shares time: {step2_time}")

            # execution stage
            gate_tape = []
            for i in range(cm): 
                gate_tape.append(1)
            for i in range(w - cm): 
                gate_tape.append(0)
            
            for i in range(layers): 
                layer_time = time.time()
                gate_outputs = await self.run_computation(new_shares, gate_tape, new_mult_triples, i)
                layer_time = time.time() - layer_time
                print(f"layer ID: {i} layer_time: {layer_time}")

            # invoke robust_rec to reconstruct the output
            rec_task = asyncio.create_task(self.rec_step(gate_outputs, 20))
            (mks, output_values) = await rec_task


            admpc_time = time.time() - start_time
            print(f"honeybadgermpc_time: {admpc_time}")

import json
# Manage all MPC instances
class ADMPC_Multi_Layer_Control():
    def __init__(self, n=None, t= None, deg=None, layer_num=None, total_cm=None, pks=None):
        self.n = n
        self.t = t
        self.deg = deg
        self.layer_num = layer_num
        self.total_cm = total_cm
        self.control_signal = asyncio.Event()
        self.pks_all = [[None] * self.n for _ in range(self.layer_num)]
        if pks is not None: 
            for layerID in range(self.layer_num): 
                self.pks_all[layerID] = pks[self.n*layerID:self.n*layerID+self.n]

    # async def add(self):
    #     """Generate layer_num * n MPC instances (stored in self.admpc_lists, corresponding run_admpc tasks stored in admpc_tasks)"""
    #     # Initialize public key groups (including all MPC instance public keys)
    #     self.pks_all = [[None] * self.n for _ in range(self.layer_num)]      # Storage format: pks_all = [[all public keys for layer 1], [all public keys for layer 2], ..., [public keys for last layer]]
    #     # Initialize admpc_lists (store all MPC instances)
    #     self.admpc_lists = [[None] * self.n for _ in range(self.layer_num)]
    #     self.admpc_tasks = [[None] * self.n for _ in range(self.layer_num)]

    #     router = SimpleRouter(self.n * self.layer_num)

    #     curve_params = (ZR, G1, multiexp, dotprod)

    #     start_time = time.time()

    #     g, h, pks, sks = get_avss_params(self.n * self.layer_num)
    #     pc = PolyCommitHybrid(g, h, ZR, multiexp)
    #     mat = gen_vector(self.t, self.n, ZR)

    #     # Generate all MPC instances
    #     for layerID in range(self.layer_num):
    #         # Generate MPC instances for each layer
    #         self.pks_all[layerID] = pks[self.n*layerID:self.n*layerID+self.n]
            
    #         # Generate each MPC instance in the layer with layerID
    #         for i in range(self.n):
    #             admpc = ADMPC_Dynamic(self.pks_all[layerID], sks[self.n * layerID + i], 
    #                                   g, h, self.n, self.t, self.deg, i, 
    #                                   router.sends[self.n * layerID + i], router.recvs[self.n * layerID + i], 
    #                                   pc, curve_params, mat, layerID, admpc_control_instance=self)
    #             self.admpc_lists[layerID][i] = admpc
    #             self.admpc_tasks[layerID][i] = asyncio.create_task(admpc.run_admpc(start_time))
            
    #     for layerID in range(self.layer_num):
    #         await asyncio.gather(*(self.admpc_tasks[layerID]))

    


class ADMPC_Dynamic(ADMPC):
    def __init__(self, public_keys, private_key, pkbls, skbls, n, t, srs, my_id, send, recv, total_cm, layers, next_pks = None, layerID = None, admpc_control_instance=None):
        self.admpc_control_instance = admpc_control_instance if admpc_control_instance is not None else ADMPC_Multi_Layer_Control(n=n, t=t, deg=t, layer_num=layers, total_cm=total_cm, pks=public_keys)
        self.layer_ID = layerID
        self.sc = ceil((t+1)/(t+1)) + 1
        self.Signal = asyncio.Event()
        super().__init__(public_keys, private_key, pkbls, skbls, n, t, srs, my_id, send, recv, next_pks=next_pks)

    async def reconstruct_values(self, trans_shares):
        """
        Robustly reconstruct original transfer values from collected shares.
        """
        tag = ADMPCMsgType.ROBUSTREC + f"_TR{self.layer_ID}"
        send, recv = self.get_send(tag), self.subscribe_recv(tag)
        # Broadcast own shares to all parties
        member_list = []
        for i in range(self.n): 
            member_list.append(self.n * (self.layer_ID) + i)
        for i in range(self.n):
            logging.info(f"[Layer {self.layer_ID}] Sending shares to sender {member_list[i]}")
            send(member_list[i], json.dumps(trans_shares).encode('utf-8'))

        # --- collect shares and robustly decode ---------------------------------
        outputs = {}
        # Prepare decoder once (RS degree‑t over n eval points)
        from optimizedhbmpc.field import GF
        from optimizedhbmpc.elliptic_curve import Subgroup
        from optimizedhbmpc.polynomial import EvalPoint
        from optimizedhbmpc.reed_solomon import DecoderFactory
        from optimizedhbmpc.utils.misc import transpose_lists

        eval_point = EvalPoint(GF(Subgroup.BLS12_381), self.n, use_omega_powers=False)
        decoder = DecoderFactory.get(eval_point)

        while True:
            # Receive next share
            sender, raw = await recv()
            shares = json.loads(raw.decode('utf-8'))
            sender_id = sender % self.n
            # Ignore duplicate senders
            if sender_id in outputs:
                continue
            outputs[sender_id] = shares

            # Attempt decoding only when we have ≥ n‑t distinct shares
            if len(outputs) < self.n - self.t:
                continue

            positions = sorted(outputs.keys())
            shares_matrix = [outputs[i] for i in positions]
            matrix = transpose_lists(shares_matrix)

            try:
                polys = decoder.decode(positions, matrix)
                # Decoding successful — return constant terms
                return [p[0] for p in polys]
            except Exception as e:
                logging.warning(
                    f"[Layer {self.layer_ID}] RS decode failed with {len(outputs)} shares "
                    f"(need up to n={self.n}); error: {e}"
                )
                # If we've already gathered all n shares and still fail ⇒ abort
                if len(outputs) == self.n:
                    raise RuntimeError(
                        f"[Layer {self.layer_ID}] Robust reconstruction failed even "
                        f"after collecting all {self.n} shares"
                    ) from e
                # Otherwise, continue waiting for more shares and retry
                continue

   
    async def run_admpc(self, start_time):
        acss_start_time = time.time()
        logging.info(f"[Layer {self.layer_ID}] Reached run_admpc checkpoint")
        
        # self.public_keys = self.public_keys[self.n*self.layer_ID:self.n*self.layer_ID+self.n]
        
        
        # cm indicates the number of multiplication gates per layer, evenly distributed across working layers
        if self.admpc_control_instance.layer_num > 2:
            cm = int(self.admpc_control_instance.total_cm / (self.admpc_control_instance.layer_num - 2))
        else:
            cm = self.admpc_control_instance.total_cm
        
        # w indicates the circuit width of each layer
        w = cm * 2
        # len_values represents the number of values that need to be passed to the next layer
        len_values = w

        # Calculate the time for each layer
        layer_time = time.time()

        # We assume that when layer_ID = 0, clients provide inputs to servers
        if self.layer_ID == 0:
            # The number of client input values should be equal to 2 * w
            inputs_num = int((2*w)/self.n)
            logging.info(f"layer ID: {self.layer_ID} inputs_num: {inputs_num}, n: {self.n}, w: {w}")
            # Sample client inputs using pySampleSecret
            # Get JSON array of random field elements from Go library
            clients_inputs = lib.pySampleSecret(inputs_num)
            # clients_inputs = json.loads(secret_json)         

            # The public keys passed here should be those of the next layer
            acss_pre_time = time.time()

            msgmode = "avss_without_proof"
            com_ab = None

            # acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1) + str(self.my_id)
            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID+1)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            self.acss = ACSS_Pre(self.next_pks, self.private_key, self.srs, 
                                 self.n, self.t, self.my_id, 
                                acsssend, acssrecv, msgmode, 
                                mpc_instance=self
                            )
            self.acss_tasks = [None] * self.n
            self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=clients_inputs))
            await self.acss_tasks[self.my_id]
            acss_pre_time = time.time() - acss_pre_time
            logging.info(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")          
            

        elif self.layer_ID == 1: 
            # Before executing this layer, servers need to: 1. receive inputs from the previous layer (note special handling for layer=1); 2. receive random values from the previous layer; 3. receive multiplication triples from the previous layer
            # Step 1: receive outputs from the previous layer (special handling for layer=1)
            recv_input_time = time.time()

            msgmode = "avss_without_proof"
            com_ab = None

            acsstag = ADMPCMsgType.ACSS + str(self.layer_ID)
            acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)

            # At this point, the current layer's public/private keys are used
            self.acss = ACSS_Foll(self.public_keys, self.private_key, self.srs, 
                                    self.n, self.t, self.my_id, 
                                    acsssend, acssrecv, msgmode, 
                                    mpc_instance=self
                            )

            self.acss_tasks = [None] * self.n
            for dealer_id in range(self.n): 
                inputs_num = int((2 * w) / self.n)
                self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, inputs_num, coms=com_ab, dealer_id=dealer_id))

            # Wait for all dealers to finish sending shares
            outputs = {}
            while True:            
                try:
                    (dealer, _, shares, commitments) = await self.acss.output_queue.get()
                    logging.info(f"layer ID: {self.layer_ID} received shares from dealer {dealer}")
                
                except asyncio.CancelledError:
                    pass 
                except Exception:
                    pass
                    
                outputs[dealer] = {'shares':shares, 'commits':commitments}
                if len(outputs) == self.n:
                    logging.info(f"layer ID: {self.layer_ID} received all shares from the previous layer")
                    break
                    

            # Merge JSON-encoded shares and commits from all dealers
            merged_shares = []
            merged_commits = []
            for dealer_id in range(self.n):
                # parse JSON bytes to Python list
                dealer_shares = json.loads(outputs[dealer_id]['shares'].decode('utf-8'))
                merged_shares.extend(dealer_shares)
                dealer_commits = json.loads(outputs[dealer_id]['commits'].decode('utf-8'))
                merged_commits.extend(dealer_commits)
            # Format init_comandproofs: combine commits as "commitment" and shares as "proof"
            clients_input_shares = {
                'commitment': merged_commits,
                'proof': merged_shares
            }

            # Split merged shares and commits for addition and multiplication gates
            total_proof = len(clients_input_shares['proof'])
            half_proof = total_proof // 2
            left_proof_inputs = clients_input_shares['proof'][:half_proof]
            right_proof_inputs = clients_input_shares['proof'][half_proof:]

            total_commit = len(clients_input_shares['commitment'])
            half_commit = total_commit // 2
            left_commit_inputs = clients_input_shares['commitment'][:half_commit]
            right_commit_inputs = clients_input_shares['commitment'][half_commit:]
            add_inputs = {
                'commitment': left_commit_inputs,
                'proof': left_proof_inputs
            }
            mul_inputs = {
                'commitment': right_commit_inputs,
                'proof': right_proof_inputs
            }
            
            # Split merged shares and commits into left and right inputs for addition gates
            total_add_proof = len(add_inputs['proof'])
            half_add_proof = total_add_proof // 2
            left_proof_inputs = add_inputs['proof'][:half_add_proof]
            right_proof_inputs = add_inputs['proof'][half_add_proof:]

            total_add_commit = len(add_inputs['commitment'])
            half_add_commit = total_add_commit // 2
            left_commit_inputs = add_inputs['commitment'][:half_add_commit]
            right_commit_inputs = add_inputs['commitment'][half_add_commit:]
            add_left_inputs = {
                'commitment': left_commit_inputs,
                'proof': left_proof_inputs
            }
            add_right_inputs = {
                'commitment': right_commit_inputs,
                'proof': right_proof_inputs
            }

            # Split merged shares and commits into left and right inputs for multiplication gates
            total_mul_proof = len(mul_inputs['proof'])
            half_mul_proof = total_mul_proof // 2
            left_proof_inputs = mul_inputs['proof'][:half_mul_proof]
            right_proof_inputs = mul_inputs['proof'][half_mul_proof:]

            total_mul_commit = len(mul_inputs['commitment'])
            half_mul_commit = total_mul_commit // 2
            left_commit_inputs = mul_inputs['commitment'][:half_mul_commit]
            right_commit_inputs = mul_inputs['commitment'][half_mul_commit:]
            mul_left_inputs = {
                'commitment': left_commit_inputs,
                'proof': left_proof_inputs
            }
            mul_right_inputs = {
                'commitment': right_commit_inputs,
                'proof': right_proof_inputs
            }
            

            logging.info(f"layer ID: {self.layer_ID} clients_input_shares length: {len(merged_shares)}")
            recv_input_time = time.time() - recv_input_time
            logging.info(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")
            # logging.info("add_left_inputs: %s", add_left_inputs)

            # Execution stage step 1: perform computation of the current layer
            exec_time = time.time()

            # invoke the Go binding for circuit addition
            ser_add_left = json.dumps(add_left_inputs).encode('utf-8')
            ser_add_right = json.dumps(add_right_inputs).encode('utf-8')
            # call pyCircuitAdd; ensure arguments are passed as bytes
            add_output_json = lib.pyCircuitAdd(ser_add_left, ser_add_right)
            # decode and parse the returned JSON
            if isinstance(add_output_json, bytes):
                add_output_json = add_output_json.decode('utf-8')
            add_outputs = json.loads(add_output_json)
            # logging.info(f"add_outputs: %s", add_outputs)
            logging.info(f"layer ID: {self.layer_ID} add_outputs length: {len(add_outputs['commitment'])}")

            exec_time = time.time() - exec_time
            logging.info(f"layer ID: {self.layer_ID} exec_time: {exec_time}")



            trans_pre_time = time.time()
            transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
            transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)
            trans_pre = Transfer_Pre(self.next_pks, self.private_key, 
                                    self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                    transsend, transrecv, cm, add_outputs, mpc_instance=self)
            trans_pre_task = asyncio.create_task(trans_pre.run_transfer())
            await trans_pre_task
            trans_pre_time = time.time() - trans_pre_time
            logging.info(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")


            mul_pre_time = time.time()
            multag = ADMPCMsgType.MUL + str(self.layer_ID+1)
            mulsend, mulrecv = self.get_send(multag), self.subscribe_recv(multag)
            mul_pre = BatchMul_Pre(self.next_pks, self.private_key, 
                                    self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                    mulsend, mulrecv, cm, mul_left_inputs, mul_right_inputs, mpc_instance=self)
            mul_pre_task = asyncio.create_task(mul_pre.run_multiply())
            await mul_pre_task
            mul_pre_time = time.time() - mul_pre_time
            logging.info(f"layer ID: {self.layer_ID} mul_pre_time: {mul_pre_time}")

        else:   
            # the client step
            if self.next_pks is None:
                trans_foll_time = time.time()
                transtag = ADMPCMsgType.TRANS + str(self.layer_ID)
                transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                trans_foll = Transfer_Foll(self.public_keys, self.private_key, 
                                self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                transsend, transrecv, cm, mpc_instance=self)

                trans_shares = await trans_foll.run_transfer(cm)
                trans_foll_time = time.time() - trans_foll_time
                logging.info(f"layer ID: {self.layer_ID} trans_foll_time: {trans_foll_time}")

                mul_foll_time = time.time()
                multag = ADMPCMsgType.MUL + str(self.layer_ID)
                mulsend, mulrecv = self.get_send(multag), self.subscribe_recv(multag)
                mul_foll = BatchMul_Foll(self.public_keys, self.private_key, 
                                self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                mulsend, mulrecv, cm, mpc_instance=self)

                new_mul_shares = await mul_foll.run_multiply(cm)
                mul_foll_time = time.time() - mul_foll_time
                logging.info(f"layer ID: {self.layer_ID} mul_foll_time: {mul_foll_time}")

                # reconstruct final values from transfer and multiplication shares
                raw_proofs = trans_shares['proof']
                logging.info(f"layer ID: {self.layer_ID} raw_proofs length: {len(raw_proofs)}")
                # Collect claimed values from transfer proofs
                claimed_values = [int(entry["ClaimedValue"]) for entry in raw_proofs]
                # Also include claimed values from multiplication shares
                raw_proofs = new_mul_shares['proof']
                claimed_values += [int(entry["ClaimedValue"]) for entry in raw_proofs]
                logging.info(f"layer ID: {self.layer_ID} combined claimed_values length: {len(claimed_values)}")
                # Perform robust reconstruction on claimed values
                output_values = await self.reconstruct_values(claimed_values)

                logging.info(f"layer ID: {self.layer_ID} reconstructed trans_values length: {len(output_values)}")


            else:

                trans_foll_time = time.time()
                transtag = ADMPCMsgType.TRANS + str(self.layer_ID)
                transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)

                trans_foll = Transfer_Foll(self.public_keys, self.private_key, 
                                self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                transsend, transrecv, cm, mpc_instance=self)

                trans_shares = await trans_foll.run_transfer(cm)
                trans_foll_time = time.time() - trans_foll_time
                logging.info(f"layer ID: {self.layer_ID} trans_foll_time: {trans_foll_time}")

                mul_foll_time = time.time()
                multag = ADMPCMsgType.MUL + str(self.layer_ID)
                mulsend, mulrecv = self.get_send(multag), self.subscribe_recv(multag)
                mul_foll = BatchMul_Foll(self.public_keys, self.private_key, 
                                self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                mulsend, mulrecv, cm, mpc_instance=self)

                new_mul_shares = await mul_foll.run_multiply(cm)
                mul_foll_time = time.time() - mul_foll_time
                logging.info(f"layer ID: {self.layer_ID} mul_foll_time: {mul_foll_time}")

                # Execution stage step 1: perform computation of the current layer
                exec_time = time.time()

                # invoke the Go binding for circuit addition
                ser_add_left = json.dumps(trans_shares).encode('utf-8')
                ser_add_right = json.dumps(trans_shares).encode('utf-8')
                # call pyCircuitAdd; ensure arguments are passed as bytes
                add_output_json = lib.pyCircuitAdd(ser_add_left, ser_add_right)
                # decode and parse the returned JSON
                if isinstance(add_output_json, bytes):
                    add_output_json = add_output_json.decode('utf-8')
                add_outputs = json.loads(add_output_json)
                # logging.info(f"add_outputs: %s", add_outputs)
                logging.info(f"layer ID: {self.layer_ID} add_outputs length: {len(add_outputs['commitment'])}")

                exec_time = time.time() - exec_time
                logging.info(f"layer ID: {self.layer_ID} exec_time: {exec_time}")



                trans_pre_time = time.time()
                transtag = ADMPCMsgType.TRANS + str(self.layer_ID+1)
                transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)
                trans_pre = Transfer_Pre(self.next_pks, self.private_key, 
                                        self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                        transsend, transrecv, cm, add_outputs, mpc_instance=self)
                trans_pre_task = asyncio.create_task(trans_pre.run_transfer())
                await trans_pre_task
                trans_pre_time = time.time() - trans_pre_time
                logging.info(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")


                mul_pre_time = time.time()
                multag = ADMPCMsgType.MUL + str(self.layer_ID+1)
                mulsend, mulrecv = self.get_send(multag), self.subscribe_recv(multag)
                mul_pre = BatchMul_Pre(self.next_pks, self.private_key, 
                                        self.pkbls, self.skbls, self.n, self.t, self.srs, self.my_id, 
                                        mulsend, mulrecv, cm, new_mul_shares, new_mul_shares, mpc_instance=self)
                mul_pre_task = asyncio.create_task(mul_pre.run_multiply())
                await mul_pre_task
                mul_pre_time = time.time() - mul_pre_time
                logging.info(f"layer ID: {self.layer_ID} mul_pre_time: {mul_pre_time}")

        layer_time = time.time() - layer_time
        logging.info(f"layer ID: {self.layer_ID} layer_time: {layer_time}")
        await asyncio.sleep(5)
        
        