import asyncio
import json
import logging
import time
from ctypes import c_char_p, c_int

from beaver.admpc2_dynamic_nonlinear import (
    ADMPC_Dynamic as _NonlinearADMPCDynamic,
    ADMPC_Multi_Layer_Control,
    ADMPCMsgType,
    lib,
)
from beaver.bgw_multiplication import BGWReduction
from beaver.hbacss import ACSS_Foll, ACSS_Pre
from beaver.transfer import Transfer_Foll, Transfer_Pre


logger = logging.getLogger(__name__)

lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype = c_char_p


class ADMPC_Dynamic(_NonlinearADMPCDynamic):
    """Naive baseline: Dumbo-MPC BGW multiplication followed by AggTrans."""

    async def _share_client_inputs_to_next_layer(self, cm):
        w = cm
        inputs_num = int((2 * w) / self.n)
        logging.info(
            "layer ID: %s inputs_num: %s, n: %s, w: %s",
            self.layer_ID,
            inputs_num,
            self.n,
            w,
        )
        clients_inputs = lib.pySampleSecret(inputs_num)

        acss_pre_time = time.time()
        acsstag = ADMPCMsgType.ACSS + str(self.layer_ID + 1)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
        self.acss = ACSS_Pre(
            self.next_pks,
            self.private_key,
            self.srs,
            self.n,
            self.t,
            self.my_id,
            acsssend,
            acssrecv,
            "avss_without_proof",
            mpc_instance=self,
        )
        self.acss_tasks = [None] * self.n
        self.acss_tasks[self.my_id] = asyncio.create_task(
            self.acss.avss(0, coms=None, values=clients_inputs)
        )
        await self.acss_tasks[self.my_id]
        acss_pre_time = time.time() - acss_pre_time
        logging.info(f"layer ID: {self.layer_ID} acss_pre_time: {acss_pre_time}")

    async def _receive_client_inputs(self, cm):
        w = cm
        inputs_num = int((2 * w) / self.n)
        recv_input_time = time.time()
        acsstag = ADMPCMsgType.ACSS + str(self.layer_ID)
        acsssend, acssrecv = self.get_send(acsstag), self.subscribe_recv(acsstag)
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
            mpc_instance=self,
        )
        self.acss_tasks = [None] * self.n
        for dealer_id in range(self.n):
            self.acss_tasks[dealer_id] = asyncio.create_task(
                self.acss.avss(0, inputs_num, coms=None, dealer_id=dealer_id)
            )

        outputs = {}
        while True:
            try:
                dealer, _, shares, commitments = await self.acss.output_queue.get()
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.exception("layer ID: %s failed receiving client input", self.layer_ID)
                continue

            outputs[dealer] = {"shares": shares, "commits": commitments}
            if len(outputs) == self.n:
                break

        merged_shares = []
        merged_commits = []
        for dealer_id in range(self.n):
            merged_shares.extend(json.loads(outputs[dealer_id]["shares"].decode("utf-8")))
            merged_commits.extend(json.loads(outputs[dealer_id]["commits"].decode("utf-8")))

        recv_input_time = time.time() - recv_input_time
        logging.info(f"layer ID: {self.layer_ID} clients_input_shares length: {len(merged_shares)}")
        logging.info(f"layer ID: {self.layer_ID} recv_input_time: {recv_input_time}")
        return {"commitment": merged_commits, "proof": merged_shares}

    def _split_inputs(self, inputs):
        total_proof = len(inputs["proof"])
        half_proof = total_proof // 2
        total_commit = len(inputs["commitment"])
        half_commit = total_commit // 2
        return (
            {
                "commitment": inputs["commitment"][:half_commit],
                "proof": inputs["proof"][:half_proof],
            },
            {
                "commitment": inputs["commitment"][half_commit:],
                "proof": inputs["proof"][half_proof:],
            },
        )

    async def _run_bgw_reduction(self, left_inputs, right_inputs, cm):
        bgw_start = time.time()
        bgwtag = ADMPCMsgType.MUL + "_BGW_" + str(self.layer_ID)
        bgwsend, bgwrecv = self.get_send(bgwtag), self.subscribe_recv(bgwtag)
        bgw = BGWReduction(
            self.public_keys,
            self.private_key,
            self.pkbls,
            self.skbls,
            self.n,
            self.t,
            self.srs,
            self.my_id,
            bgwsend,
            bgwrecv,
            cm,
            self,
        )
        try:
            out = await bgw.run_multiply(left_inputs, right_inputs)
        finally:
            bgw.kill()
        bgw_time = time.time() - bgw_start
        logging.info(f"layer ID: {self.layer_ID} bgw_time: {bgw_time}")
        return out, bgw_time

    async def _send_aggtrans_to_next_layer(self, values, cm):
        trans_pre_time = time.time()
        transtag = ADMPCMsgType.TRANS + str(self.layer_ID + 1)
        transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)
        trans_pre = Transfer_Pre(
            self.next_pks,
            self.private_key,
            self.pkbls,
            self.skbls,
            self.n,
            self.t,
            self.srs,
            self.my_id,
            transsend,
            transrecv,
            cm,
            values,
            mpc_instance=self,
        )
        trans_pre_task = asyncio.create_task(trans_pre.run_transfer())
        await trans_pre_task
        trans_pre_time = time.time() - trans_pre_time
        logging.info(f"layer ID: {self.layer_ID} trans_pre_time: {trans_pre_time}")

    async def _receive_aggtrans_from_prev_layer(self, cm):
        trans_foll_time = time.time()
        transtag = ADMPCMsgType.TRANS + str(self.layer_ID)
        transsend, transrecv = self.get_send(transtag), self.subscribe_recv(transtag)
        trans_foll = Transfer_Foll(
            self.public_keys,
            self.private_key,
            self.pkbls,
            self.skbls,
            self.n,
            self.t,
            self.srs,
            self.my_id,
            transsend,
            transrecv,
            cm,
            mpc_instance=self,
        )
        trans_shares = await trans_foll.run_transfer(cm)
        trans_foll_time = time.time() - trans_foll_time
        logging.info(f"layer ID: {self.layer_ID} trans_foll_time: {trans_foll_time}")
        return trans_shares, trans_foll_time

    async def run_admpc(self, start_time):
        logging.info(f"[Layer {self.layer_ID}] Reached BGW+AggTrans checkpoint")

        if self.admpc_control_instance.layer_num > 2:
            cm = int(
                self.admpc_control_instance.total_cm
                / (self.admpc_control_instance.layer_num - 2)
            )
        else:
            cm = self.admpc_control_instance.total_cm

        layer_time = time.time()

        if self.layer_ID == 0:
            await self._share_client_inputs_to_next_layer(cm)

        elif self.layer_ID == 1:
            client_inputs = await self._receive_client_inputs(cm)
            left_inputs, right_inputs = self._split_inputs(client_inputs)
            bgw_outputs, _ = await self._run_bgw_reduction(left_inputs, right_inputs, cm)
            if self.next_pks is not None:
                await self._send_aggtrans_to_next_layer(bgw_outputs, cm)
            else:
                raw_proofs = bgw_outputs["proof"]
                claimed_values = [int(entry["ClaimedValue"]) for entry in raw_proofs]
                output_values = await self.reconstruct_values(claimed_values)
                logging.info(
                    f"layer ID: {self.layer_ID} reconstructed trans_values length: {len(output_values)}"
                )

        else:
            trans_shares, trans_foll_time = await self._receive_aggtrans_from_prev_layer(cm)
            if self.next_pks is None:
                logging.info(
                    f"layer ID: {self.layer_ID} trusted_verification_time: {trans_foll_time}"
                )
                raw_proofs = trans_shares["proof"]
                claimed_values = [int(entry["ClaimedValue"]) for entry in raw_proofs]
                logging.info(
                    f"layer ID: {self.layer_ID} combined claimed_values length: {len(claimed_values)}"
                )
                output_values = await self.reconstruct_values(claimed_values)
                logging.info(
                    f"layer ID: {self.layer_ID} reconstructed trans_values length: {len(output_values)}"
                )
            else:
                bgw_outputs, bgw_time = await self._run_bgw_reduction(
                    trans_shares, trans_shares, cm
                )
                logging.info(
                    f"layer ID: {self.layer_ID} bgw_aggtrans_time: {trans_foll_time + bgw_time}"
                )
                logging.info(
                    f"layer ID: {self.layer_ID} trusted_verification_time: {trans_foll_time + bgw_time}"
                )
                await self._send_aggtrans_to_next_layer(bgw_outputs, cm)

        layer_time = time.time() - layer_time
        logging.info(f"layer ID: {self.layer_ID} layer_time: {layer_time}")
        await asyncio.sleep(5)
