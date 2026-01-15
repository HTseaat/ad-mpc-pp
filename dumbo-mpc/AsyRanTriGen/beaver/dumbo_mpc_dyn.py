import logging
import asyncio
from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.utils.misc import wrap_send, subscribe_recv
from beaver.hbacss import Hbacss1
import time
from ctypes import *
import json
import os
from optimizedhbmpc.mpc import Mpc
from optimizedhbmpc.field import GF
from optimizedhbmpc.elliptic_curve import Subgroup

lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p

lib.pyRandomShareCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyRandomShareCompute.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerify.restype = c_bool

lib.pyTriplesCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyTriplesCompute.restype = c_char_p

lib.pyReconstruct.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]

class BeaverMsgType:
    ACSS1 = "R_A"
    ACSS2 = "B_A"
    ACS1 = "ACS1"
    ACS2 = "ACS2"
    
class BEAVER:
    def __init__(self, public_keys,  private_key, pkbls, skbls, n, t, srs, my_id, send, recv, matrices, batchsize, layers=10):

        global logger 
        logfile = f'./log/logs-{my_id}.log'

        logging.basicConfig(
            level=logging.INFO,
            format = '%(asctime)s:[%(filename)s:%(lineno)s]:[%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile,  
            filemode='w'
        )
    
        logger= logging.getLogger(__name__)
        
        self.public_keys, self.private_key, self.pkbls, self.skbls = (public_keys, private_key, pkbls, skbls)
        self.n, self.t, self.srs, self.my_id = (n, t, srs, my_id)
        self.send, self.recv = (send, recv)
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.matrix = matrices
        self.batchsize = batchsize
        self.layers = int(layers)

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )
        
    def __enter__(self):
        return self    
        
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("Beaver task finished")
        

    def __exit__(self, type, value, traceback):
        return self
    
    def genrandomshare(self, acsset, acss_outputs):
        acsset_list = list(acsset)
        acsset_list.sort()
        serialized_acsset = json.dumps(acsset_list).encode('utf-8')
    
        commitment = [None] * self.n
        proofsandshares = [None] * self.n
        for i in acsset:
            commitment[i] = json.loads(acss_outputs[i]['commits'].decode('utf-8'))
            proofsandshares[i] = json.loads(acss_outputs[i]['shares'].decode('utf-8'))

        serialized_commitments = json.dumps(commitment).encode('utf-8')
        serialized_proofandshares = json.dumps(proofsandshares).encode('utf-8')
        
        return lib.pyRandomShareCompute(self.matrix, serialized_acsset, 
                                        serialized_commitments, serialized_proofandshares, self.t)

    def beavergen(self, acsset, acss_outputs, sharesproofs_ab):
        acsset_list = list(acsset)
        acsset_list.sort()
        serialized_acsset = json.dumps(acsset_list).encode('utf-8')
    
        commitment = [None] * self.n
        proofsandshares = [None] * self.n
        for i in acsset:
            commitment[i] = json.loads(acss_outputs[i]['commits'].decode('utf-8'))
            proofsandshares[i] = json.loads(acss_outputs[i]['shares'].decode('utf-8'))

        # filtered_commitments = [item for item in commitment if item is not None ]
        serialized_commitments = json.dumps(commitment).encode('utf-8')
        serialized_proofandshares = json.dumps(proofsandshares).encode('utf-8')


        deserialized_commandprooflist = json.loads(sharesproofs_ab.decode('utf-8')) 
        serialized_share_ab = json.dumps(deserialized_commandprooflist["proof"]).encode('utf-8')
        serialized_triples = lib.pyTriplesCompute(serialized_acsset, serialized_share_ab, serialized_proofandshares, serialized_commitments)
        return serialized_triples   

    async def acss_step(self, msgmode, outputs, values, acss_signal, acss_tag=None):
        acsstag = acss_tag or BeaverMsgType.ACSS1
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        logger.info(f"[{self.my_id}] [ACSS] Using tag {acsstag} (mode={msgmode})")
        com_ab = None
        if msgmode == "avss_with_proof":
            deser_comsandproofs = json.loads(values.decode('utf-8'))
            com_ab = json.dumps(deser_comsandproofs['commitment']).encode('utf-8')
        self.acss = Hbacss1(self.public_keys, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, dealer_id=i))
        
        while True:            
            try:
                (dealer, _, shares, commitments) = await self.acss.output_queue.get()
               
            except asyncio.CancelledError:
                pass 
            except Exception:
                pass
            except:
                pass
                
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            if len(outputs) >= self.n - self.t:
                acss_signal.set()
            # await asyncio.sleep(0.01)

            if len(outputs) == self.n:
                return
    
    async def reduction(self, msgmode, outputs, values, acss_signal):
        
        acsstag = BeaverMsgType.ACSS2
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        if msgmode == "avss_with_proof":
            deser_comsandproofs = json.loads(values.decode('utf-8'))
            # logging.info("deser_comsandproofs: %s", deser_comsandproofs)
            com_ab = json.dumps(deser_comsandproofs['commitment']).encode('utf-8')
        self.acss = Hbacss1(self.public_keys, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, dealer_id=i))
        
        while True:            
            try:
                (dealer, _, shares, commitments) = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                pass 
            except Exception:
                pass
            except:
                pass
                
            outputs[dealer] = {'shares':shares, 'commits':commitments}
            if len(outputs) >= self.n - self.t:
                acss_signal.set()
            await asyncio.sleep(0.01)

            if len(outputs) == self.n:
                return
    
    async def run_beaver(self, node_communicator):
        logger.info(f"[{self.my_id}] Starting AsyRanTriGen")
        acss_outputs = {}
        acss_signal = asyncio.Event()        

        try:
            pkbls_bytes = self.pkbls.to_bytes()
            logger.info("self.pkbls (hex): %s", pkbls_bytes.hex())
        except AttributeError:
            logger.info("self.pkbls: %s", self.pkbls)
        try:
            skbls_bytes = self.skbls.to_bytes()
            logger.info("self.skbls (hex): %s", skbls_bytes.hex())
        except AttributeError:
            logger.info("self.skbls: %s", self.skbls)


        acss_start_time = time.time()
        values = lib.pySampleSecret(self.batchsize)

        logger.info(f"[{self.my_id}] Starting ACSS to share {self.batchsize} secrets")
        self.acss_task = asyncio.create_task(self.acss_step("avss_without_proof", acss_outputs, values, acss_signal, acss_tag=BeaverMsgType.ACSS1))
        await acss_signal.wait()
        acss_signal.clear()
        # try: self.acss_task.cancel()
        # except Exception: pass
        key_proposal = list(acss_outputs.keys())        
        
        acstag = BeaverMsgType.ACS1
        acssend, acsrecv = self.get_send(acstag), self.subscribe_recv(acstag)
        leader = 1
        
        logger.info(f"[{self.my_id}] [random shares] Starting ACS where node {leader} is set as leader ")
        logger.info(f"[{self.my_id}] [random shares] The proposal of node {self.my_id} is {key_proposal}")
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
            acss_outputs,
            acss_signal
        )
        acsset = await acs.handle_message()
        logger.info(f"[{self.my_id}] [random shares] The ACS set is {acsset}") 

        logger.info(f"[{self.my_id}] Starting extract random shares") 
        randomshares_proofs = self.genrandomshare(acsset, acss_outputs)
            
        acss_outputs = [None]
        logger.info(f"[{self.my_id}] Obtaining total {(self.t + 1) * self.batchsize} random shares!")

        
        logger.info(f"[{self.my_id}] Starting to generate beaver triples")
        logger.info(f"[{self.my_id}] [beaver triples] Starting to share random shares") 
        reduction_outputs = {}
        reduction_values = randomshares_proofs
        # logging.info("reduction_values: %s", reduction_values)
        reduction_signal = asyncio.Event()
        self.acss_task = asyncio.create_task(self.reduction("avss_with_proof", reduction_outputs, reduction_values, reduction_signal))
        await reduction_signal.wait()
        reduction_signal.clear()
        # try: self.acss_task.cancel()
        # except Exception: pass
        reduction_proposal = list(reduction_outputs.keys())
        
        acstag_beaver = BeaverMsgType.ACS2 # (R, msg)
        acssend, acsrecv = self.get_send(acstag_beaver), self.subscribe_recv(acstag_beaver)
        leader = 2
        logger.info(f"[{self.my_id}] [beaver triples] Starting to ACS where {leader} is set as leader ")

        logger.info(f"[{self.my_id}] [beaver triples] The proposal of node {self.my_id} is {reduction_proposal}")                
        acs = OptimalCommonSet(
            acstag_beaver,
            self.my_id,
            self.n,
            self.t,
            leader,
            reduction_proposal,
            self.pkbls,
            self.skbls,
            acssend, 
            acsrecv,
            reduction_outputs,
            reduction_signal
        )
        acsset_beaver = await acs.handle_message()
        logger.info(f"[{self.my_id}] [beaver triples] The ACS set is {acsset_beaver}") 
        
        triples = self.beavergen(acsset_beaver, reduction_outputs, reduction_values)
        beaver_time = time.time() -acss_start_time

        logger.info(f"[{self.my_id}] [beaver triples] Time taken for beaver_time: {beaver_time} seconds")

        # logger.info("triples: %s", triples)

        inputs_time = time.time()

        # layers = 10
        layers = self.layers
        total_cm = self.batchsize
        cm =  total_cm // layers
        if cm <= 0:
            raise ValueError(
                f"Invalid params: batchsize={total_cm}, layers={layers} -> cm={cm}. "
                f"Need batchsize >= layers (and preferably divisible) to proceed."
            )
        w = cm * 2

        # === Generate public inputs via ACSS+ACS and linear combination ===
        # Goal: each party ACSS-broadcasts a length-(2*w) random vector; after ACS agrees on a common dealer set,
        #       every party sums (coordinate-wise) the local shares from dealers in the set to obtain 2*w input shares.
        inputs_len = 2 * w
        logger.info(f"[{self.my_id}] [inputs] Start generating {inputs_len} public inputs via ACSS+ACS")

        # 1) ACSS broadcast of random vectors (length = inputs_len)
        inputs_outputs = {}
        inputs_signal = asyncio.Event()
        values_inputs = lib.pySampleSecret(inputs_len)
        logger.info(f"[{self.my_id}] [inputs] Starting ACSS to share {inputs_len} inputs")
        self.acss_task = asyncio.create_task(self.acss_step("avss_without_proof", inputs_outputs, values_inputs, inputs_signal, acss_tag="ACSS_INPUTS_AVSS"))
        await inputs_signal.wait()
        inputs_signal.clear()
        # try: self.acss_task.cancel()
        # except Exception: pass
        proposal_inputs = list(inputs_outputs.keys())

        # 2) Run ACS to agree on a common subset of dealers
        acstag_inputs = "ACS_INPUTS"
        acssend_in, acsrecv_in = self.get_send(acstag_inputs), self.subscribe_recv(acstag_inputs)
        leader_inputs = 0
        logger.info(f"[{self.my_id}] [inputs] Starting ACS (leader={leader_inputs}); proposal size={len(proposal_inputs)}")
        acs_inputs = OptimalCommonSet(
            acstag_inputs,
            self.my_id,
            self.n,
            self.t,
            leader_inputs,
            proposal_inputs,
            self.pkbls,
            self.skbls,
            acssend_in,
            acsrecv_in,
            inputs_outputs,
            inputs_signal,
        )
        acsset_inputs = await acs_inputs.handle_message()
        logger.info(f"[{self.my_id}] [inputs] ACS set size={len(acsset_inputs)}; set={acsset_inputs}")

        # logger.info("inputs_outputs[0]: %s", inputs_outputs[0])

        # === Decode inputs from inputs_outputs[0] and prepare (x,y) ===
        def _decode_local_vector_from_acss(shares_bytes, my_id):
            """Decode ACSS output into a flat list of field-representatives (ints).
            Supports:
            (A) per-receiver container (list/dict) -> pick entry for my_id
            (B) list of objects with key 'ClaimedValue'
            """
            obj = json.loads(shares_bytes.decode("utf-8"))

            # Case B: list of dicts each having ClaimedValue  —— 这是你日志的格式
            if isinstance(obj, list) and obj and isinstance(obj[0], dict) and ("ClaimedValue" in obj[0]):
                raw_vals = [item.get("ClaimedValue") for item in obj]
                res = []
                for v in raw_vals:
                    if isinstance(v, int):
                        res.append(v)
                    elif isinstance(v, str):
                        res.append(int(v, 16) if v.lower().startswith("0x") else int(v))
                    else:
                        res.append(int(v))
                return res

            # Case A: old per-receiver container
            if isinstance(obj, list):
                vec = obj[my_id]
            elif isinstance(obj, dict):
                key = str(my_id) if str(my_id) in obj else my_id
                vec = obj[key]
            else:
                raise ValueError("Unexpected ACSS shares encoding for inputs")

            res = []
            for x in vec:
                if isinstance(x, int):
                    res.append(x)
                elif isinstance(x, str):
                    res.append(int(x, 16) if x.lower().startswith("0x") else int(x))
                else:
                    res.append(int(x))
            return res
        # Use inputs from dealer 0 directly as requested
        input_vec0 = _decode_local_vector_from_acss(inputs_outputs[0]['shares'], self.my_id)
        logger.info(f"[{self.my_id}] [inputs] Decoded {len(input_vec0)} input shares from dealer 0")
        # logger.info("[{self.my_id}] [inputs] input_vec0: %s", input_vec0)
        # Determine batch size M from cm (number of multiplications per layer)
        M = cm
        if len(input_vec0) < 2 * M:
            logger.warning(f"[{self.my_id}] [mul] input_vec0 length {len(input_vec0)} < 2*M={2*M}; will truncate M accordingly")
            M = len(input_vec0) // 2
        x_shares = input_vec0[:M]
        y_shares = input_vec0[M:2*M]
        field = GF(Subgroup.BLS12_381)
        I = [field(v) for v in input_vec0[: 2*w]]  # I_1

        # === Decode local Beaver triples (a,b,c) from `triples` ===
        def _decode_triples_local(serialized_triples, my_id, count):
            """Decode triples into three lists (a,b,c) of length `count`.
            Supports:
            (1) Local scalar lists: {"A":[..], "B":[..], "C":[..]}
            (2) Per-receiver containers: {"a": <list/dict>, ...}
            """
            try:
                obj = json.loads(serialized_triples.decode('utf-8'))
            except Exception as e:
                logger.error(f"[{self.my_id}] [mul] Cannot decode triples as JSON: {e}")
                return None, None, None

            def _to_ints(vec):
                out = []
                for v in vec:
                    if isinstance(v, int):
                        out.append(v)
                    elif isinstance(v, str):
                        try:
                            out.append(int(v, 16) if v.lower().startswith('0x') else int(v))
                        except Exception:
                            out.append(int(v))
                    else:
                        out.append(int(v))
                return out

            # Case (1): A/B/C 直接是本地标量数组（你的实际格式）
            if all(k in obj for k in ('A','B','C')) \
            and isinstance(obj['A'], list) and isinstance(obj['B'], list) and isinstance(obj['C'], list) \
            and (not obj['A'] or not isinstance(obj['A'][0], (list, dict))):
                a_list = _to_ints(obj['A'])
                b_list = _to_ints(obj['B'])
                c_list = _to_ints(obj['C'])
                if len(a_list) < count or len(b_list) < count or len(c_list) < count:
                    logger.warning(f"[{self.my_id}] [mul] triples shorter than needed; will truncate M")
                return a_list[:count], b_list[:count], c_list[:count]

            # Case (2): 旧的“按接收方”容器
            def _pick(container):
                if isinstance(container, list):
                    vec = container[self.my_id]
                elif isinstance(container, dict):
                    key = str(self.my_id) if str(self.my_id) in container else self.my_id
                    vec = container[key]
                else:
                    raise ValueError("Unexpected triples encoding container")
                return vec

            try:
                a_vec = _pick(obj.get('a', obj.get('A', [])))
                b_vec = _pick(obj.get('b', obj.get('B', [])))
                c_vec = _pick(obj.get('c', obj.get('C', [])))
            except Exception as e:
                logger.error(f"[{self.my_id}] [mul] Triples container structure not recognized: {e}")
                return None, None, None

            a_list = _to_ints(a_vec)
            b_list = _to_ints(b_vec)
            c_list = _to_ints(c_vec)
            if len(a_list) < count or len(b_list) < count or len(c_list) < count:
                logger.warning(f"[{self.my_id}] [mul] triples shorter than needed; will truncate M")
            return a_list[:count], b_list[:count], c_list[:count]

        a_all, b_all, c_all = _decode_triples_local(triples, self.my_id, total_cm)
        logger.info("len a_all: %d, len b_all: %d, len c_all: %d", len(a_all), len(b_all), len(c_all))
        # logger.info("[{self.my_id}] [mul] Decoded triples: a_shares=%s, b_shares=%s, c_shares=%s", a_all, b_all, c_all)

        field = GF(Subgroup.BLS12_381)
        triple_cursor = 0
        last_outputs = None

        inputs_time = time.time() - inputs_time
        logger.info(f"[{self.my_id}] [inputs] Time taken to inputs_time: {inputs_time} seconds")

        for L in range(layers):
            # # 第4层(从1开始数) => L==3；让 0/1 号节点跳过该层以模拟“下线/不参与”
            # if self.my_id in (0, 1) and L == 3:
            #     logger.warning(f"[{self.my_id}] [layer {L}] Simulate offline: skip layer {L} (4th layer)")
            #     continue

            # triples slice for this layer
            layer_time = time.time()
            take = cm
            logger.info(f"[{self.my_id}] [layer {L}] Using {take} triples (a,b,c) for multiplication")
            a_slice = [field(v) for v in a_all[triple_cursor : triple_cursor + take]]
            b_slice = [field(v) for v in b_all[triple_cursor : triple_cursor + take]]
            c_slice = [field(v) for v in c_all[triple_cursor : triple_cursor + take]]
            triple_cursor += take

            if len(I) < 2*w:
                logger.warning(f"[{self.my_id}] [L{L}] Input length {len(I)} < 2*w={2*w}; truncating")
                I = I[:2*w]

            # partition inputs: first 2*cm => mul, next 2*cm => add
            x_fe = I[0:cm]
            y_fe = I[cm:2*cm]
            u_fe = I[2*cm:3*cm]
            v_fe = I[3*cm:4*cm]

            # Beaver: open gammas/epsilons in batch
            gammas   = [x_fe[i] - a_slice[i] for i in range(cm)]
            epsilons = [y_fe[i] - b_slice[i] for i in range(cm)]


            tag_open = f"OPENING_MUL_L{L}"
            send_open = self.get_send(tag_open)
            recv_open = self.subscribe_recv(tag_open)

            async def prog_open(ctx):
                return await ctx.ShareArray(gammas + epsilons, self.t).open()

            os.makedirs('sharedata_test', exist_ok=True)
            ctx_open = Mpc(f"mpc:opening-mul-L{L}", self.n, self.t, self.my_id, send_open, recv_open, prog_open, {})
            pubs = await ctx_open._run()
            gamma_pub = pubs[:cm]
            epsilon_pub = pubs[cm:]

            # mul + add
            z_mul = [
                c_slice[i] + gamma_pub[i] * b_slice[i] + epsilon_pub[i] * a_slice[i] + gamma_pub[i] * epsilon_pub[i]
                for i in range(cm)
            ]
            z_add = [u_fe[i] + v_fe[i] for i in range(cm)]

            O_L = z_mul + z_add     # |O_L| = w
            last_outputs = O_L
            I = O_L + O_L           # 下一层输入长度 2*w
            logger.info(f"[{self.my_id}] [layer {L}] done: produced {len(O_L)} outputs; next I size={len(I)}")
            layer_time = time.time() - layer_time
            logger.info(f"[{self.my_id}] [layer {L}] Time taken for layer layer_time: {layer_time} seconds")

        # === Final reconstruction of last layer outputs ===
        rec_time = time.time()
        tag_final = "OPENING_FINAL"
        send_fin = self.get_send(tag_final)
        recv_fin = self.subscribe_recv(tag_final)

        async def prog_final(ctx):
            return await ctx.ShareArray(last_outputs, self.t).open()

        logger.info(f"[{self.my_id}] [final] opening {len(last_outputs)} outputs")
        ctx_final = Mpc("mpc:opening-final", self.n, self.t, self.my_id, send_fin, recv_fin, prog_final, {})
        final_vals = await ctx_final._run()
        logger.info(f"[{self.my_id}] [final] reconstructed {len(final_vals)} values")
        rec_time = time.time() - rec_time
        logger.info(f"[{self.my_id}] [final] Time taken for reconstruction rec_time: {rec_time} seconds")

        # if a_shares is None:
        #     logger.error(f"[{self.my_id}] [mul] Abort multiplication: triples not decodable")
        # else:
        #     # === Beaver-style multiplication with one batched opening ===
        #     # Compute gamma=x-a and epsilon=y-b locally (t-shared)
        #     field = GF(Subgroup.BLS12_381)
        #     x_fe = [field(v) for v in x_shares]
        #     y_fe = [field(v) for v in y_shares]
        #     a_fe = [field(v) for v in a_shares]
        #     b_fe = [field(v) for v in b_shares]
        #     c_fe = [field(v) for v in c_shares]

        #     logger.info("x_fe: %s", x_fe)

        #     # 在域里计算差值（自动 mod p）
        #     gammas   = [x_fe[i] - a_fe[i] for i in range(M)]
        #     epsilons = [y_fe[i] - b_fe[i] for i in range(M)]

        #     # Open [gamma] and [epsilon] using Mpc.ShareArray(...).open()
        #     tag_open = "OPENING_MUL"
        #     # 复用 BEAVER.__init__ 里建立的 splitter，避免与 ACSS/ACS 串扰
        #     send_open = self.get_send(tag_open)
        #     recv_open = self.subscribe_recv(tag_open)

        #     logger.info(f"[{self.my_id}] [mul] Starting opening of {M} gamma and epsilon values")
        #     async def prog_open(ctx):
        #         pubs = await ctx.ShareArray(gammas + epsilons, self.t).open()
        #         return pubs

        #     logger.info("before Mpc")
            
        #     # ctx_open = Mpc("mpc:opening-mul", self.n, self.t, self.my_id, send_open, recv_open, prog_open, {})
        #     # logger.info("after Mpc")
        #     try:
        #         os.makedirs('sharedata_test', exist_ok=True)  # 防掉目录不存在
        #         ctx_open = Mpc("mpc:opening-mul", self.n, self.t, self.my_id, send_open, recv_open, prog_open, {})
        #         logger.info("after Mpc")
        #     except Exception as e:
        #         logger.exception(f"[{self.my_id}] [mul] Failed to construct Mpc context: {e}")
        #         raise
        #     pubs = await ctx_open._run()
        #     logger.info(f"[{self.my_id}] [mul] Opened {len(pubs)} values (gamma + epsilon)")

        #     gamma_pub_fe = pubs[:M]
        #     epsilon_pub_fe = pubs[M:]

        #     z_fe = [
        #         c_fe[i] +
        #         gamma_pub_fe[i]   * b_fe[i] +
        #         epsilon_pub_fe[i] * a_fe[i] +
        #         gamma_pub_fe[i]   * epsilon_pub_fe[i]
        #         for i in range(M)
        #     ]
        #     logger.info(f"[{self.my_id}] [mul] Computed {M} multiplications: z_fe={z_fe}")  
        #     # 输出落盘用整型代表元
        #     z_shares = [int(v) for v in z_fe]
        #     logger.info(f"[{self.my_id}] [mul] Computed {M} multiplications: z_shares={z_shares}")

        
        reduction_outputs = [None]
        computation_time = time.time() - acss_start_time    
        logger.info(f"[{self.my_id}] [beaver triples] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {computation_time} (seconds)")

        
        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        while True:
            await asyncio.sleep(2)