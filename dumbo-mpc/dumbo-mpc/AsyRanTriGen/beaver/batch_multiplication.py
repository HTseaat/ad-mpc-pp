import logging
from Crypto.Util.number import long_to_bytes
import asyncio
from beaver.broadcast.otmvba_dyn import OptimalCommonSet
from beaver.utils.misc import wrap_send, subscribe_recv
from beaver.hbacss import Hbacss1, ACSS_Pre, ACSS_Foll
import time
from ctypes import *
import json
import sys
import struct

lib_bulletproof = CDLL("./libbulletproofs_amcl.so")

lib_bulletproof.pyProveFactors.argtypes = [c_char_p]
# lib_bulletproof.pyProveFactors.restype = c_char_p
lib_bulletproof.pyProveFactors.restype = c_void_p

# lib_bulletproof.pyFreeString.argtypes = [c_char_p]
lib_bulletproof.pyFreeString.argtypes = [c_void_p]  # ✅ 必须匹配！
lib_bulletproof.pyFreeString.restype = None

lib_bulletproof.pyVerifyFactors.argtypes = [c_char_p]
# lib_bulletproof.pyVerifyFactors.restype = 
lib_bulletproof.pyVerifyFactors.restype = c_void_p  # ✅ 正确类型！


lib = CDLL("./kzg_ped_out.so")

lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p

lib.pyRandomShareCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyRandomShareCompute.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerify.restype = c_bool

lib.pyTriplesCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyTriplesCompute.restype = c_char_p

lib.pyMultiplyClaimedValuesWithAux.argtypes = [c_char_p, c_char_p]
lib.pyMultiplyClaimedValuesWithAux.restype = c_char_p

lib.pyCommitWithZeroFull.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyCommitWithZeroFull.restype  = c_char_p

lib.pyPedersenCommit.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyPedersenCommit.restype = c_char_p

lib.pyComputeShareGH.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyComputeShareGH.restype = c_char_p

lib.pyReconstruct.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]

lib.pyInterpolateShareswithTransfer.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyInterpolateShareswithTransfer.restype  = c_char_p


class BatchMultiplicationMsg:
    ACSS = "BM_ACSS"
    ACS  = "BM_ACS"

class BatchMultiplication:
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,                    # I/O
                 batchsize,                     # B secrets
                 comandproof_left_inputs= None, 
                 comandproof_right_inputs= None):                   # list of KZG commitments C_k^l, local secret shares [s_k^l],evaluation proofs [w_k^l]

        
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
        self.batchsize = batchsize

        # Algorithm 2 inputs
        self.comandproof_left_inputs = comandproof_left_inputs       
        self.comandproof_right_inputs = comandproof_right_inputs   

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
    
    async def acss_step(self, msgmode, outputs, values, acss_signal):
        acsstag = BatchMultiplicationMsg.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        self.acss = Hbacss1(self.public_keys, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, dealer_id=i))

        # Track the majority (left_commitments, right_commitments) value once we discover it
        majority_oc = None

        while True:
            try:
                (dealer, _, shares, commitments, left_commitments, right_commitments) = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            except:
                pass

            outputs[dealer] = {
                'shares': shares,
                'commits': commitments,
                'left_commitments': left_commitments,
                'right_commitments': right_commitments
            }
            # -----------------------------------------------
            # Majority (left_commitments, right_commitments) tracking & pruning
            # -----------------------------------------------
            if majority_oc is not None:
                # Majority already chosen – discard any dealer that disagrees
                if (left_commitments, right_commitments) != majority_oc:
                    outputs.pop(dealer, None)
                    continue
            else:
                # Still searching for a consensus (left_commitments, right_commitments)
                commit_counter = {}
                for d, v in outputs.items():
                    key = (v['left_commitments'], v['right_commitments'])
                    commit_counter[key] = commit_counter.get(key, 0) + 1
                # Check if some (left_commitments, right_commitments) appears ≥ n‑t times
                for oc_val, count in commit_counter.items():
                    if count >= self.n - self.t:
                        majority_oc = oc_val
                        # Prune all dealers whose (left_commitments, right_commitments) differ
                        for del_d in list(outputs.keys()):
                            val = (outputs[del_d]['left_commitments'], outputs[del_d]['right_commitments'])
                            if val != majority_oc:
                                outputs.pop(del_d, None)
                        acss_signal.set()  # consensus reached
                        break

            if len(outputs) == self.n:
                return


    async def run_multiply(self, node_communicator):

        logger.info(f"[{self.my_id}] Starting BatchMultiplication")  

        serialized_left_proof = json.dumps(self.comandproof_left_inputs["proof"]).encode('utf-8')
        serialized_right_proof = json.dumps(self.comandproof_right_inputs["proof"]).encode('utf-8')

        # logger.info("serialized_left_proof: %s", serialized_left_proof)
        # logger.info("serialized_right_proof: %s", serialized_right_proof)

        # Example usage of the new Go function:
        result = lib.pyMultiplyClaimedValuesWithAux(serialized_left_proof, serialized_right_proof)
        deser_result = json.loads(result.decode('utf-8'))

        secrets = deser_result["value"]
        secrets_aux = deser_result["aux"]

        # logger.info("secrets: %s", secrets)

        left_vec  = [int(entry["ClaimedValue"]) for entry in json.loads(serialized_left_proof.decode("utf-8"))]
        right_vec = [int(entry["ClaimedValue"]) for entry in json.loads(serialized_right_proof.decode("utf-8"))]
        out_vec   = [int(x) for x in secrets]

        # logger.info("left_vec: %s", left_vec)
        # logger.info("right_vec: %s", right_vec)
        # logger.info("out_vec: %s", out_vec)

        left_aux_vec  = [int(entry["ClaimedValueAux"]) for entry in json.loads(serialized_left_proof.decode("utf-8"))]
        right_aux_vec = [int(entry["ClaimedValueAux"]) for entry in json.loads(serialized_right_proof.decode("utf-8"))]
        out_aux_vec   = [int(x) for x in secrets_aux]

        # logger.info("left_aux_vec: %s", left_aux_vec)
        # logger.info("right_aux_vec: %s", right_aux_vec)
        # logger.info("out_aux_vec: %s", out_aux_vec)

        pk_dict = json.loads(self.srs["Pk"].decode("utf-8"))
        g0 = pk_dict["G1_g"][0]
        h0 = pk_dict["G1_h"][0]

        # read G1_g[0] X/Y 
        gx_dec = int(g0["X"])
        gy_dec = int(g0["Y"])

        # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
        # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

        gx_bytes = long_to_bytes(gx_dec, 48)
        gy_bytes = long_to_bytes(gy_dec, 48)

        uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
        uncompressed_g_hex = uncompressed_g.hex()
        # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

        # add h0
        hx_dec = int(h0["X"])
        hy_dec = int(h0["Y"])

        # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
        # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

        hx_bytes = long_to_bytes(hx_dec, 48)
        hy_bytes = long_to_bytes(hy_dec, 48)

        uncompressed_h = b'\x04' + hx_bytes + hy_bytes
        uncompressed_h_hex = uncompressed_h.hex()
        # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())

        # construct the witness vector
        witnesses = []
        for p_dec, q_dec, r_dec, p_blind_dec, q_blind_dec, r_blind_dec in zip(left_vec, right_vec, out_vec, left_aux_vec, right_aux_vec, out_aux_vec):
            witnesses.append({
                "p": hex(p_dec)[2:],  # delete '0x' 
                "q": hex(q_dec)[2:],
                "r": hex(r_dec)[2:],
                "p_blind": hex(p_blind_dec)[2:],
                "q_blind": hex(q_blind_dec)[2:],
                "r_blind": hex(r_blind_dec)[2:]
            })

        # logger.info("witnesses: %s", witnesses)

        # construct Rust ProveInput 
        prove_input = {
            "witnesses": witnesses,
            "g": uncompressed_g_hex,
            "h": uncompressed_h_hex
        }
        input_json = json.dumps(prove_input).encode("utf-8")

        # generate inner product proof
        proof_ptr = lib_bulletproof.pyProveFactors(input_json)
        
        # extract proof and commitments
        res = json.loads(string_at(proof_ptr).decode("utf-8"))
        proof = res["proof"]
        commitments = res["commitments"]
        # logger.info("proof: %s", proof)

        # logger.info("pyProveFactors commitments: %s", commitments)
        logger.info("Proof hex length: %d", len(proof))
        logger.info("Proof size (bytes): %d", len(proof) // 2)
        proof_bytes = bytes.fromhex(proof)
        logger.info("Proof size (strict bytes): %d", len(proof_bytes))

        # parsed_commitments = []
        # for item in commitments:
        #     x_hex, y_hex = item.strip("()").split(",")
        #     parsed_commitments.append({
        #         "X": str(int(x_hex, 16)),
        #         "Y": str(int(y_hex, 16))
        #     })
        # logger.info("parsed_commitments: %s", parsed_commitments)
        


        # Combine left, right, result, and proof into a unified dictionary
        inputs = {
            "left": self.comandproof_left_inputs,
            "right": self.comandproof_right_inputs,
            "result": deser_result,
            "proof": proof
        }

        acss_start_time = time.time()
        acss_outputs = {}
        acss_signal = asyncio.Event()

        logger.info(f"[{self.my_id}] Starting ACSS to evaluate {self.batchsize} multiplication gates")
        self.acss_task = asyncio.create_task(self.acss_step("avss_with_batch_multiplication", acss_outputs, inputs, acss_signal))
        # self.acss_task = asyncio.create_task(self.acss_step("avss_with_aggbatch_multiplication", acss_outputs, inputs, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        key_proposal = list(acss_outputs.keys())

        logging.info("key_proposal: %s", key_proposal)
        # logging.info("acss_outputs: %s", acss_outputs)
        
        acstag = BatchMultiplicationMsg.ACS
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

        # Lagrange Interpolation
        common = sorted(list(acsset))
        logging.info("common: %s", common)
        ser_common = json.dumps(common).encode('utf-8')

        commits_sel = [json.loads(acss_outputs[i]['commits'].decode())
                    for i in common]
        shares_sel  = [json.loads(acss_outputs[i]['shares'].decode())
                    for i in common]

        ser_commit = json.dumps(commits_sel).encode('utf-8')
        ser_share  = json.dumps(shares_sel).encode('utf-8')


        interpolated = lib.pyInterpolateShareswithTransfer(ser_common, ser_commit, ser_share)
        transfer_time = time.time() -acss_start_time
        # logger.info("interpolated = %s", interpolated)

        # # ---- Verify the interpolated commitment/proof pair (evaluation at x = 0) ----
        # deser_interp = json.loads(interpolated.decode("utf-8"))
        # serialized_interp_commit = json.dumps(deser_interp["commitment"]).encode("utf-8")
        # serialized_interp_proof  = json.dumps(deser_interp["shares"]).encode("utf-8")

        # verify_ok = lib.pyBatchVerify(
        #     self.srs["Vk"],                 # VerifyingKey
        #     serialized_interp_commit,       # commitments
        #     serialized_interp_proof,        # proof+shares
        #     self.my_id                              # idx = -1 → “evaluation at x = 0”
        # )
        # logger.info("[interpolation-check] BatchVerify => %s", bool(verify_ok))

        # sys.exit(0)
        
        # The time it takes to write the triples to the file is not included in the total time overhead
        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'wb') as file:
                file.write(byte_data)

        write_bytes_to_file(f'transfer/{self.my_id}_transfer.txt', interpolated)
        
        logger.info(f"[{self.my_id}] [asynchronous batch multiplication] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {transfer_time} (seconds)")

        
        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        while True:
            await asyncio.sleep(2)


class BatchMul_Pre(BatchMultiplication):
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,                    # I/O
                 batchsize,                     # B secrets
                 comandproof_left_inputs, 
                 comandproof_right_inputs, mpc_instance):                   # list of KZG commitments C_k^l, local secret shares [s_k^l],evaluation proofs [w_k^l]

        
        self.mpc_instance = mpc_instance
        serialized_pk_bytes = json.dumps(public_keys).encode('utf-8')
        super().__init__(serialized_pk_bytes, private_key, pkbls, skbls, n, t, srs, my_id, send, recv, batchsize, comandproof_left_inputs, comandproof_right_inputs)


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
    
    async def acss_step(self, msgmode, outputs, values, acss_signal):

        layerID = self.mpc_instance.layer_ID
        acsstag = BatchMultiplicationMsg.ACSS + str(layerID+1)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        decoded_next_pks = json.loads(self.public_keys.decode('utf-8'))
        self.acss = ACSS_Pre(decoded_next_pks, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode, mpc_instance=self.mpc_instance)
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))


        # # Track the majority (left_commitments, right_commitments) value once we discover it
        # majority_oc = None

        # while True:
        #     try:
        #         (dealer, _, shares, commitments, left_commitments, right_commitments) = await self.acss.output_queue.get()
        #     except asyncio.CancelledError:
        #         pass
        #     except Exception:
        #         pass
        #     except:
        #         pass

        #     outputs[dealer] = {
        #         'shares': shares,
        #         'commits': commitments,
        #         'left_commitments': left_commitments,
        #         'right_commitments': right_commitments
        #     }
        #     # -----------------------------------------------
        #     # Majority (left_commitments, right_commitments) tracking & pruning
        #     # -----------------------------------------------
        #     if majority_oc is not None:
        #         # Majority already chosen – discard any dealer that disagrees
        #         if (left_commitments, right_commitments) != majority_oc:
        #             outputs.pop(dealer, None)
        #             continue
        #     else:
        #         # Still searching for a consensus (left_commitments, right_commitments)
        #         commit_counter = {}
        #         for d, v in outputs.items():
        #             key = (v['left_commitments'], v['right_commitments'])
        #             commit_counter[key] = commit_counter.get(key, 0) + 1
        #         # Check if some (left_commitments, right_commitments) appears ≥ n‑t times
        #         for oc_val, count in commit_counter.items():
        #             if count >= self.n - self.t:
        #                 majority_oc = oc_val
        #                 # Prune all dealers whose (left_commitments, right_commitments) differ
        #                 for del_d in list(outputs.keys()):
        #                     val = (outputs[del_d]['left_commitments'], outputs[del_d]['right_commitments'])
        #                     if val != majority_oc:
        #                         outputs.pop(del_d, None)
        #                 acss_signal.set()  # consensus reached
        #                 break

        #     if len(outputs) == self.n:
        #         return


    async def run_multiply(self):

        logger.info(f"[{self.my_id}] Starting BatchMultiplication")  

        serialized_left_proof = json.dumps(self.comandproof_left_inputs["proof"]).encode('utf-8')
        serialized_right_proof = json.dumps(self.comandproof_right_inputs["proof"]).encode('utf-8')

        # logger.info("serialized_left_proof: %s", serialized_left_proof)
        # logger.info("serialized_right_proof: %s", serialized_right_proof)

        # Example usage of the new Go function:
        result = lib.pyMultiplyClaimedValuesWithAux(serialized_left_proof, serialized_right_proof)
        deser_result = json.loads(result.decode('utf-8'))

        secrets = deser_result["value"]
        secrets_aux = deser_result["aux"]

        # logger.info("secrets: %s", secrets)

        left_vec  = [int(entry["ClaimedValue"]) for entry in json.loads(serialized_left_proof.decode("utf-8"))]
        right_vec = [int(entry["ClaimedValue"]) for entry in json.loads(serialized_right_proof.decode("utf-8"))]
        out_vec   = [int(x) for x in secrets]

        left_aux_vec  = [int(entry["ClaimedValueAux"]) for entry in json.loads(serialized_left_proof.decode("utf-8"))]
        right_aux_vec = [int(entry["ClaimedValueAux"]) for entry in json.loads(serialized_right_proof.decode("utf-8"))]
        out_aux_vec   = [int(x) for x in secrets_aux]


        pk_dict = json.loads(self.srs["Pk"].decode("utf-8"))
        g0 = pk_dict["G1_g"][0]
        h0 = pk_dict["G1_h"][0]

        # read G1_g[0] X/Y 
        gx_dec = int(g0["X"])
        gy_dec = int(g0["Y"])

        # logging.info("X_hex: %s", hex(gx_dec)[2:].zfill(96).upper())
        # logging.info("Y_hex: %s", hex(gy_dec)[2:].zfill(96).upper())

        gx_bytes = long_to_bytes(gx_dec, 48)
        gy_bytes = long_to_bytes(gy_dec, 48)

        uncompressed_g = b'\x04' + gx_bytes + gy_bytes  # 0x04 + X || Y (uncompressed form)
        uncompressed_g_hex = uncompressed_g.hex()
        # logging.info("uncompressed.hex(): %s", uncompressed_g.hex())

        # add h0
        hx_dec = int(h0["X"])
        hy_dec = int(h0["Y"])

        # logging.info("HX_hex: %s", hex(hx_dec)[2:].zfill(96).upper())
        # logging.info("HY_hex: %s", hex(hy_dec)[2:].zfill(96).upper())

        hx_bytes = long_to_bytes(hx_dec, 48)
        hy_bytes = long_to_bytes(hy_dec, 48)

        uncompressed_h = b'\x04' + hx_bytes + hy_bytes
        uncompressed_h_hex = uncompressed_h.hex()
        # logging.info("uncompressed_h.hex(): %s", uncompressed_h.hex())

        # construct the witness vector
        witnesses = []
        for p_dec, q_dec, r_dec, p_blind_dec, q_blind_dec, r_blind_dec in zip(left_vec, right_vec, out_vec, left_aux_vec, right_aux_vec, out_aux_vec):
            witnesses.append({
                "p": hex(p_dec)[2:],  # delete '0x' 
                "q": hex(q_dec)[2:],
                "r": hex(r_dec)[2:],
                "p_blind": hex(p_blind_dec)[2:],
                "q_blind": hex(q_blind_dec)[2:],
                "r_blind": hex(r_blind_dec)[2:]
            })

        # logger.info("witnesses: %s", witnesses)

        # construct Rust ProveInput 
        prove_input = {
            "witnesses": witnesses,
            "g": uncompressed_g_hex,
            "h": uncompressed_h_hex
        }
        input_json = json.dumps(prove_input).encode("utf-8")

        # generate inner product proof
        proof_ptr = lib_bulletproof.pyProveFactors(input_json)
        
        # extract proof and commitments
        res = json.loads(string_at(proof_ptr).decode("utf-8"))
        proof = res["proof"]
        commitments = res["commitments"]
        # logger.info("proof: %s", proof)

        # logger.info("pyProveFactors commitments: %s", commitments)
        logger.info("Proof hex length: %d", len(proof))
        logger.info("Proof size (bytes): %d", len(proof) // 2)
        proof_bytes = bytes.fromhex(proof)
        logger.info("Proof size (strict bytes): %d", len(proof_bytes))

        # parsed_commitments = []
        # for item in commitments:
        #     x_hex, y_hex = item.strip("()").split(",")
        #     parsed_commitments.append({
        #         "X": str(int(x_hex, 16)),
        #         "Y": str(int(y_hex, 16))
        #     })
        # logger.info("parsed_commitments: %s", parsed_commitments)
        


        # Combine left, right, result, and proof into a unified dictionary
        inputs = {
            "left": self.comandproof_left_inputs,
            "right": self.comandproof_right_inputs,
            "result": deser_result,
            "proof": proof
        }

        acss_start_time = time.time()
        acss_outputs = {}
        acss_signal = asyncio.Event()

        logger.info(f"[{self.my_id}] Starting ACSS to evaluate {self.batchsize} multiplication gates")
        # self.acss_task = asyncio.create_task(self.acss_step("avss_with_batch_multiplication", acss_outputs, inputs, acss_signal))
        self.acss_task = asyncio.create_task(self.acss_step("avss_with_aggbatch_multiplication", acss_outputs, inputs, acss_signal))
        
        # await acss_signal.wait()
        # acss_signal.clear()
        # key_proposal = list(acss_outputs.keys())

        # logging.info("key_proposal: %s", key_proposal)
        # # logging.info("acss_outputs: %s", acss_outputs)
        
        # acstag = BatchMultiplicationMsg.ACS
        # acssend, acsrecv = self.get_send(acstag), self.subscribe_recv(acstag)
        # leader = 1
        
        # logger.info(f"[{self.my_id}] [random shares] Starting ACS where node {leader} is set as leader ")
        # logger.info(f"[{self.my_id}] [random shares] The proposal of node {self.my_id} is {key_proposal}")
        # acs = OptimalCommonSet(
        #     acstag,
        #     self.my_id,
        #     self.n,
        #     self.t,
        #     leader,
        #     key_proposal,
        #     self.pkbls,
        #     self.skbls,
        #     acssend, 
        #     acsrecv,
        #     acss_outputs,
        #     acss_signal
        # )
        # acsset = await acs.handle_message()
        # logger.info(f"[{self.my_id}] [random shares] The ACS set is {acsset}") 

        # # Lagrange Interpolation
        # common = sorted(list(acsset))
        # logging.info("common: %s", common)
        # ser_common = json.dumps(common).encode('utf-8')

        # commits_sel = [json.loads(acss_outputs[i]['commits'].decode())
        #             for i in common]
        # shares_sel  = [json.loads(acss_outputs[i]['shares'].decode())
        #             for i in common]

        # ser_commit = json.dumps(commits_sel).encode('utf-8')
        # ser_share  = json.dumps(shares_sel).encode('utf-8')


        # interpolated = lib.pyInterpolateShareswithTransfer(ser_common, ser_commit, ser_share)
        # transfer_time = time.time() -acss_start_time
        # # logger.info("interpolated = %s", interpolated)

        # # # ---- Verify the interpolated commitment/proof pair (evaluation at x = 0) ----
        # # deser_interp = json.loads(interpolated.decode("utf-8"))
        # # serialized_interp_commit = json.dumps(deser_interp["commitment"]).encode("utf-8")
        # # serialized_interp_proof  = json.dumps(deser_interp["shares"]).encode("utf-8")

        # # verify_ok = lib.pyBatchVerify(
        # #     self.srs["Vk"],                 # VerifyingKey
        # #     serialized_interp_commit,       # commitments
        # #     serialized_interp_proof,        # proof+shares
        # #     self.my_id                              # idx = -1 → “evaluation at x = 0”
        # # )
        # # logger.info("[interpolation-check] BatchVerify => %s", bool(verify_ok))

        # # sys.exit(0)
        
        # # The time it takes to write the triples to the file is not included in the total time overhead
        # def write_bytes_to_file(file_path, byte_data):
        #     with open(file_path, 'wb') as file:
        #         file.write(byte_data)

        # write_bytes_to_file(f'transfer/{self.my_id}_transfer.txt', interpolated)
        
        # logger.info(f"[{self.my_id}] [asynchronous batch multiplication] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {transfer_time} (seconds)")

        
        # bytes_sent = node_communicator.bytes_sent
        # for k,v in node_communicator.bytes_count.items():
        #     logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        # logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        # while True:
        #     await asyncio.sleep(2)

class BatchMul_Foll(BatchMultiplication ):
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,                    # I/O
                 batchsize,                     # B secrets
                 mpc_instance):                   

        self.mpc_instance = mpc_instance
        super().__init__(public_keys, private_key, pkbls, skbls, n, t, srs, my_id, send, recv, batchsize)
        
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
    
    async def acss_step(self, msgmode, outputs, mul_num, acss_signal):

        layerID = self.mpc_instance.layer_ID
        acsstag = BatchMultiplicationMsg.ACSS + str(layerID)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        self.acss = ACSS_Foll(self.public_keys, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode, mpc_instance=self.mpc_instance)
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n):
            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, mul_num, coms=com_ab, dealer_id=dealer_id))


        # Track the majority (left_commitments, right_commitments) value once we discover it
        majority_oc = None

        while True:
            try:
                (dealer, _, shares, commitments, left_commitments, right_commitments) = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            except:
                pass

            outputs[dealer] = {
                'shares': shares,
                'commits': commitments,
                'left_commitments': left_commitments,
                'right_commitments': right_commitments
            }
            # -----------------------------------------------
            # Majority (left_commitments, right_commitments) tracking & pruning
            # -----------------------------------------------
            if majority_oc is not None:
                # Majority already chosen – discard any dealer that disagrees
                if (left_commitments, right_commitments) != majority_oc:
                    outputs.pop(dealer, None)
                    continue
            else:
                # Still searching for a consensus (left_commitments, right_commitments)
                commit_counter = {}
                for d, v in outputs.items():
                    key = (v['left_commitments'], v['right_commitments'])
                    commit_counter[key] = commit_counter.get(key, 0) + 1
                # Check if some (left_commitments, right_commitments) appears ≥ n‑t times
                for oc_val, count in commit_counter.items():
                    if count >= self.n - self.t:
                        majority_oc = oc_val
                        # Prune all dealers whose (left_commitments, right_commitments) differ
                        for del_d in list(outputs.keys()):
                            val = (outputs[del_d]['left_commitments'], outputs[del_d]['right_commitments'])
                            if val != majority_oc:
                                outputs.pop(del_d, None)
                        acss_signal.set()  # consensus reached
                        break

            if len(outputs) == self.n:
                return


    async def run_multiply(self, mul_num):

        logger.info(f"[{self.my_id}] Starting BatchMultiplication")  

        acss_start_time = time.time()
        acss_outputs = {}
        acss_signal = asyncio.Event()

        logger.info(f"[{self.my_id}] Starting ACSS to evaluate {self.batchsize} multiplication gates")
        # self.acss_task = asyncio.create_task(self.acss_step("avss_with_batch_multiplication", acss_outputs, inputs, acss_signal))
        self.acss_task = asyncio.create_task(self.acss_step("avss_with_aggbatch_multiplication", acss_outputs, mul_num, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        key_proposal = list(acss_outputs.keys())

        logging.info("key_proposal: %s", key_proposal)
        # logging.info("acss_outputs: %s", acss_outputs)
        
        acstag = BatchMultiplicationMsg.ACS + str(self.mpc_instance.layer_ID)
        acssend, acsrecv = self.get_send(acstag), self.subscribe_recv(acstag)
        leader = 1
        member_list = []
        for i in range(self.n): 
            member_list.append(self.n * (self.mpc_instance.layer_ID) + i)
        
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
            acss_signal, 
            member_list
        )
        acsset = await acs.handle_message_dyn()
        logger.info(f"[{self.my_id}] [random shares] The ACS set is {acsset}") 

        # Lagrange Interpolation
        common = sorted(list(acsset))
        logging.info("common: %s", common)
        ser_common = json.dumps(common).encode('utf-8')

        commits_sel = [json.loads(acss_outputs[i]['commits'].decode())
                    for i in common]
        shares_sel  = [json.loads(acss_outputs[i]['shares'].decode())
                    for i in common]

        ser_commit = json.dumps(commits_sel).encode('utf-8')
        ser_share  = json.dumps(shares_sel).encode('utf-8')


        interpolated = lib.pyInterpolateShareswithTransfer(ser_common, ser_commit, ser_share)
        transfer_time = time.time() -acss_start_time
        deser_interp = json.loads(interpolated.decode("utf-8"))
        # logger.info("interpolated = %s", interpolated)

        # # ---- Verify the interpolated commitment/proof pair (evaluation at x = 0) ----
        # deser_interp = json.loads(interpolated.decode("utf-8"))
        # serialized_interp_commit = json.dumps(deser_interp["commitment"]).encode("utf-8")
        # serialized_interp_proof  = json.dumps(deser_interp["shares"]).encode("utf-8")

        # verify_ok = lib.pyBatchVerify(
        #     self.srs["Vk"],                 # VerifyingKey
        #     serialized_interp_commit,       # commitments
        #     serialized_interp_proof,        # proof+shares
        #     self.my_id                              # idx = -1 → “evaluation at x = 0”
        # )
        # logger.info("[interpolation-check] BatchVerify => %s", bool(verify_ok))

        # sys.exit(0)
        
        # The time it takes to write the triples to the file is not included in the total time overhead
        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'wb') as file:
                file.write(byte_data)

        write_bytes_to_file(f'transfer/{self.my_id}_transfer.txt', interpolated)
        
        logger.info(f"[{self.my_id}] [asynchronous batch multiplication] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {transfer_time} (seconds)")

        # normalize output format: rename 'shares' to 'proof'
        if "shares" in deser_interp:
            deser_interp["proof"] = deser_interp.pop("shares")
        return deser_interp

        


