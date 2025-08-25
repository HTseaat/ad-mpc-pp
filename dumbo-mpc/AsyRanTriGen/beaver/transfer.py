import logging
import asyncio
from beaver.broadcast.otmvba_dyn import OptimalCommonSet
from beaver.utils.misc import wrap_send, subscribe_recv
from beaver.hbacss import Hbacss1, ACSS_Pre, ACSS_Foll
import time
from ctypes import *
import json
import sys

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

lib.pyInterpolateShareswithTransfer.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyInterpolateShareswithTransfer.restype  = c_char_p


class DynamicTransferMsg:
    ACSS = "DT_ACSS"
    ACS  = "DT_ACS"

class DynamicTransfer:
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,                    # I/O
                 batchsize,                     # B secrets
                 init_comandproofs=None):                   # list of KZG commitments C_k^l, local secret shares [s_k^l],evaluation proofs [w_k^l]

        
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

        # Algorithm 1 inputs
        self.initial_comandproofs = init_comandproofs          

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
        
        acsstag = DynamicTransferMsg.ACSS
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        self.acss = Hbacss1(self.public_keys, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode)
        self.acss_tasks = [None] * self.n
        for i in range(self.n):
            if i == self.my_id:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))
            else:
                self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, dealer_id=i))

        # Track the majority original_commitments value once we discover it
        majority_oc = None

        while True:            
            try:
                (dealer, _, shares, commitments, original_commitments) = await self.acss.output_queue.get()
               
            except asyncio.CancelledError:
                pass 
            except Exception:
                pass
            except:
                pass
                
            outputs[dealer] = {'shares': shares, 'commits': commitments, 'original_commits': original_commitments}
            # -----------------------------------------------
            # Majority‑original_commitments tracking & pruning
            # -----------------------------------------------
            if majority_oc is not None:
                # Majority already chosen – discard any dealer that disagrees
                if original_commitments != majority_oc:
                    # Remove the just‑added inconsistent dealer
                    outputs.pop(dealer, None)
                    continue
            else:
                # Still searching for a consensus original_commitments
                commit_counter = {}
                for d, v in outputs.items():
                    oc = v['original_commits']
                    commit_counter[oc] = commit_counter.get(oc, 0) + 1
                # Check if some oc appears ≥ n‑t times
                for oc_val, count in commit_counter.items():
                    if count >= self.n - self.t:
                        majority_oc = oc_val
                        # Prune all dealers whose original_commitments differ
                        for del_d in list(outputs.keys()):
                            if outputs[del_d]['original_commits'] != majority_oc:
                                outputs.pop(del_d, None)
                        acss_signal.set()  # consensus reached
                        break

            # await asyncio.sleep(0.01)

            if len(outputs) == self.n:
                return



    async def run_transfer(self, node_communicator):

        logger.info(f"[{self.my_id}] Starting DynamicTransfer")        
        serialized_initial_comandproofs = json.dumps(self.initial_comandproofs).encode('utf-8')

        # logging.info("serialized_initial_comandproofs: %s", serialized_initial_comandproofs)

        acss_start_time = time.time()
        acss_outputs = {}
        acss_signal = asyncio.Event()        

        logger.info(f"[{self.my_id}] Starting ACSS to share {self.batchsize} secrets")
        # self.acss_task = asyncio.create_task(self.acss_step("avss_with_transfer", acss_outputs, serialized_initial_comandproofs, acss_signal))
        self.acss_task = asyncio.create_task(self.acss_step("avss_with_aggtransfer", acss_outputs, serialized_initial_comandproofs, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        key_proposal = list(acss_outputs.keys())        

        logging.info("key_proposal: %s", key_proposal)
        # logging.info("acss_outputs: %s", acss_outputs)
        
        acstag = DynamicTransferMsg.ACS
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

        logging.info("commits_sel: %s", commits_sel)
        logging.info("shares_sel: %s", shares_sel)

        ser_commit = json.dumps(commits_sel).encode('utf-8')
        ser_share  = json.dumps(shares_sel).encode('utf-8')


        interpolated = lib.pyInterpolateShareswithTransfer(ser_common, ser_commit, ser_share)
        transfer_time = time.time() -acss_start_time
        # logger.info("interpolated = %s", interpolated)

        # ---- Verify the interpolated commitment/proof pair (evaluation at x = 0) ----
        deser_interp = json.loads(interpolated.decode("utf-8"))
        serialized_interp_commit = json.dumps(deser_interp["commitment"]).encode("utf-8")
        serialized_interp_proof  = json.dumps(deser_interp["shares"]).encode("utf-8")

        verify_ok = lib.pyBatchVerify(
            self.srs["Vk"],                 # VerifyingKey
            serialized_interp_commit,       # commitments
            serialized_interp_proof,        # proof+shares
            self.my_id                              # idx = -1 → “evaluation at x = 0”
        )
        logger.info("[interpolation-check] BatchVerify => %s", bool(verify_ok))

        # sys.exit(0)
        
        # The time it takes to write the triples to the file is not included in the total time overhead
        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'wb') as file:
                file.write(byte_data)

        write_bytes_to_file(f'transfer/{self.my_id}_transfer.txt', interpolated)
        
        logger.info(f"[{self.my_id}] [asynchronous dynamic transfer] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {transfer_time} (seconds)")

        
        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        while True:
            await asyncio.sleep(2)


class Transfer_Pre(DynamicTransfer):
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,                    # I/O
                 batchsize,                     # B secrets
                 init_comandproofs, mpc_instance):                   # list of KZG commitments C_k^l, local secret shares [s_k^l],evaluation proofs [w_k^l]

        
        self.mpc_instance = mpc_instance
        serialized_pk_bytes = json.dumps(public_keys).encode('utf-8')

        super().__init__(serialized_pk_bytes, private_key, pkbls, skbls, n, t, srs, my_id, send, recv, batchsize, init_comandproofs)
        
        
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
        logging.info(f"[{self.my_id}] [asynchronous dynamic transfer] Layer ID: {layerID}")
        acsstag = DynamicTransferMsg.ACSS + str(layerID+1)

        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        decoded_next_pks = json.loads(self.public_keys.decode('utf-8'))
        self.acss = ACSS_Pre(decoded_next_pks, self.private_key, self.srs, 
                                 self.n, self.t, self.my_id, 
                                acsssend, acssrecv, msgmode, 
                                mpc_instance=self.mpc_instance
                            )
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))

        # # Track the majority original_commitments value once we discover it
        # majority_oc = None

        # while True:            
        #     try:
        #         (dealer, _, shares, commitments, original_commitments) = await self.acss.output_queue.get()
               
        #     except asyncio.CancelledError:
        #         pass 
        #     except Exception:
        #         pass
        #     except:
        #         pass
                
        #     outputs[dealer] = {'shares': shares, 'commits': commitments, 'original_commits': original_commitments}
        #     # -----------------------------------------------
        #     # Majority‑original_commitments tracking & pruning
        #     # -----------------------------------------------
        #     if majority_oc is not None:
        #         # Majority already chosen – discard any dealer that disagrees
        #         if original_commitments != majority_oc:
        #             # Remove the just‑added inconsistent dealer
        #             outputs.pop(dealer, None)
        #             continue
        #     else:
        #         # Still searching for a consensus original_commitments
        #         commit_counter = {}
        #         for d, v in outputs.items():
        #             oc = v['original_commits']
        #             commit_counter[oc] = commit_counter.get(oc, 0) + 1
        #         # Check if some oc appears ≥ n‑t times
        #         for oc_val, count in commit_counter.items():
        #             if count >= self.n - self.t:
        #                 majority_oc = oc_val
        #                 # Prune all dealers whose original_commitments differ
        #                 for del_d in list(outputs.keys()):
        #                     if outputs[del_d]['original_commits'] != majority_oc:
        #                         outputs.pop(del_d, None)
        #                 acss_signal.set()  # consensus reached
        #                 break

        #     # await asyncio.sleep(0.01)

        #     if len(outputs) == self.n:
        #         return



    async def run_transfer(self):

        logger.info(f"[{self.my_id}] Starting DynamicTransfer")        
        serialized_initial_comandproofs = json.dumps(self.initial_comandproofs).encode('utf-8')

        # logging.info("serialized_initial_comandproofs: %s", serialized_initial_comandproofs)
        
        acss_start_time = time.time()
        acss_outputs = {}
        acss_signal = asyncio.Event()        

        logger.info(f"[{self.my_id}] Starting ACSS to share {self.batchsize} secrets")
        # import sys; sys.exit(0)



        self.acss_task = asyncio.create_task(self.acss_step("avss_with_aggtransfer", acss_outputs, serialized_initial_comandproofs, acss_signal))
        # await acss_signal.wait()
        # acss_signal.clear()
        # key_proposal = list(acss_outputs.keys())        

        # logging.info("key_proposal: %s", key_proposal)
        # # logging.info("acss_outputs: %s", acss_outputs)
        
        # acstag = DynamicTransferMsg.ACS
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

        # logging.info("commits_sel: %s", commits_sel)
        # logging.info("shares_sel: %s", shares_sel)

        # ser_commit = json.dumps(commits_sel).encode('utf-8')
        # ser_share  = json.dumps(shares_sel).encode('utf-8')


        # interpolated = lib.pyInterpolateShareswithTransfer(ser_common, ser_commit, ser_share)
        # transfer_time = time.time() -acss_start_time
        # # logger.info("interpolated = %s", interpolated)

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

        # # sys.exit(0)
        
        # # The time it takes to write the triples to the file is not included in the total time overhead
        # def write_bytes_to_file(file_path, byte_data):
        #     with open(file_path, 'wb') as file:
        #         file.write(byte_data)

        # write_bytes_to_file(f'transfer/{self.my_id}_transfer.txt', interpolated)
        
        # logger.info(f"[{self.my_id}] [asynchronous dynamic transfer] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {transfer_time} (seconds)")

        
        # bytes_sent = node_communicator.bytes_sent
        # for k,v in node_communicator.bytes_count.items():
        #     logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        # logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        # while True:
        #     await asyncio.sleep(2)


class Transfer_Foll(DynamicTransfer):
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,                    # I/O
                 batchsize,                     # B secrets
                 mpc_instance):                 # mpc_instance

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
    
    async def acss_step(self, msgmode, outputs, trans_num, acss_signal):
        
        layerID = self.mpc_instance.layer_ID
        acsstag = DynamicTransferMsg.ACSS + str(layerID)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        com_ab = None
        self.acss = ACSS_Foll(self.public_keys, self.private_key, self.srs, self.n, self.t, self.my_id, acsssend, acssrecv, msgmode, mpc_instance=self.mpc_instance)
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n):
            self.acss_tasks[dealer_id] = asyncio.create_task(self.acss.avss(0, trans_num, coms=com_ab, dealer_id=dealer_id))
        # for i in range(self.n):
        #     if i == self.my_id:
        #         self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, values=values))
        #     else:
        #         self.acss_tasks[i] = asyncio.create_task(self.acss.avss(0, coms=com_ab, dealer_id=i))

        # Track the majority original_commitments value once we discover it
        majority_oc = None

        while True:            
            try:
                (dealer, _, shares, commitments, original_commitments) = await self.acss.output_queue.get()
               
            except asyncio.CancelledError:
                pass 
            except Exception:
                pass
            except:
                pass
                
            outputs[dealer] = {'shares': shares, 'commits': commitments, 'original_commits': original_commitments}
            # -----------------------------------------------
            # Majority‑original_commitments tracking & pruning
            # -----------------------------------------------
            if majority_oc is not None:
                # Majority already chosen – discard any dealer that disagrees
                if original_commitments != majority_oc:
                    # Remove the just‑added inconsistent dealer
                    outputs.pop(dealer, None)
                    continue
            else:
                # Still searching for a consensus original_commitments
                commit_counter = {}
                for d, v in outputs.items():
                    oc = v['original_commits']
                    commit_counter[oc] = commit_counter.get(oc, 0) + 1
                # Check if some oc appears ≥ n‑t times
                for oc_val, count in commit_counter.items():
                    if count >= self.n - self.t:
                        majority_oc = oc_val
                        # Prune all dealers whose original_commitments differ
                        for del_d in list(outputs.keys()):
                            if outputs[del_d]['original_commits'] != majority_oc:
                                outputs.pop(del_d, None)
                        acss_signal.set()  # consensus reached
                        break

            # await asyncio.sleep(0.01)

            if len(outputs) == self.n:
                return



    async def run_transfer(self, trans_num):

        logger.info(f"[{self.my_id}] Starting DynamicTransfer_Foll")        


        acss_start_time = time.time()
        acss_outputs = {}
        acss_signal = asyncio.Event()        

        logger.info(f"[{self.my_id}] Starting ACSS to share {self.batchsize} secrets")
        # self.acss_task = asyncio.create_task(self.acss_step("avss_with_transfer", acss_outputs, serialized_initial_comandproofs, acss_signal))
        self.acss_task = asyncio.create_task(self.acss_step("avss_with_aggtransfer", acss_outputs, trans_num, acss_signal))
        await acss_signal.wait()
        acss_signal.clear()
        key_proposal = list(acss_outputs.keys())        

        logging.info("key_proposal: %s", key_proposal)
        # logging.info("acss_outputs: %s", acss_outputs)
        
        acstag = DynamicTransferMsg.ACS + str(self.mpc_instance.layer_ID)
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

        # logging.info("commits_sel: %s", commits_sel)
        # logging.info("shares_sel: %s", shares_sel)

        ser_commit = json.dumps(commits_sel).encode('utf-8')
        ser_share  = json.dumps(shares_sel).encode('utf-8')


        interpolated = lib.pyInterpolateShareswithTransfer(ser_common, ser_commit, ser_share)
        transfer_time = time.time() -acss_start_time
        deser_interp = json.loads(interpolated.decode("utf-8"))
        # logger.info("interpolated = %s", deser_interp)

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
        
        logger.info(f"[{self.my_id}] [asynchronous dynamic transfer] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {transfer_time} (seconds)")

        # normalize output format: rename 'shares' to 'proof'
        if "shares" in deser_interp:
            deser_interp["proof"] = deser_interp.pop("shares")
        return deser_interp

        
        # bytes_sent = node_communicator.bytes_sent
        # for k,v in node_communicator.bytes_count.items():
        #     logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        # logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        # while True:
        #     await asyncio.sleep(2)
