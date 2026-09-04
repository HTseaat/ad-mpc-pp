import asyncio
import json
import logging
import os
import time
from ctypes import c_char_p

from beaver.admpc2_dynamic import (
    ADMPC_Dynamic as _BaseADMPCDynamic,
    ADMPC_Multi_Layer_Control,
    ADMPCMsgType,
    lib,
)
from beaver.batch_multiplication_local import BatchMulLocal
from beaver.batch_rand_bit import BatchRandBit_Foll, BatchRandBit_Pre
from beaver.hbacss import ACSS_Foll, ACSS_Pre
from beaver.shuffle_network import build_butterfly_schedule
from beaver.transfer import Transfer_Foll, Transfer_Pre
from optimizedhbmpc.elliptic_curve import Subgroup


logger = logging.getLogger(__name__)
FIELD_MODULUS = int(Subgroup.BLS12_381)
INV_TWO = (FIELD_MODULUS + 1) // 2

HAS_LINEAR_COMB = hasattr(lib, "pyCircuitLinearComb")
if HAS_LINEAR_COMB:
    lib.pyCircuitLinearComb.argtypes = [c_char_p, c_char_p]
    lib.pyCircuitLinearComb.restype = c_char_p


class ADMPC_Dynamic(_BaseADMPCDynamic):
    """Shuffle / mixing-network benchmark built from BatchMulLocal + AggTrans."""

    def _shuffle_mode(self):
        return (os.getenv("SHUFFLE_MODE") or "single").strip().lower()

    def _handoff_interval(self, switch_layers):
        raw_value = (os.getenv("SHUFFLE_HANDOFF_INTERVAL") or "1").strip().lower()
        if raw_value in {"static", "none", "no-handoff", "nohandoff", "inf", "infinity"}:
            return switch_layers

        interval = int(raw_value)
        if interval <= 0:
            raise ValueError("SHUFFLE_HANDOFF_INTERVAL must be positive or static")
        return min(interval, switch_layers)

    def _handoff_grace_seconds(self):
        raw_value = (os.getenv("SHUFFLE_HANDOFF_GRACE_SECONDS") or "30").strip()
        grace_seconds = float(raw_value)
        if grace_seconds < 0:
            raise ValueError("SHUFFLE_HANDOFF_GRACE_SECONDS must be non-negative")
        return grace_seconds

    def _retain_handoff_resource(self, resource):
        if not hasattr(self, "_outgoing_handoff_resources"):
            self._outgoing_handoff_resources = []
        self._outgoing_handoff_resources.append(resource)

    def _release_handoff_resources(self):
        resources = getattr(self, "_outgoing_handoff_resources", [])
        self._outgoing_handoff_resources = []
        for resource in resources:
            kill = getattr(resource, "kill", None)
            if kill is None:
                continue
            try:
                kill()
            except Exception:
                logging.debug(
                    "layer ID: %s failed to release outgoing handoff resource",
                    self.layer_ID,
                    exc_info=True,
                )

    async def _keep_sender_alive_after_handoff(self, next_layer_id):
        grace_seconds = self._handoff_grace_seconds()
        try:
            if grace_seconds <= 0:
                return
            logging.info(
                "layer ID: %s keeping handoff sender alive for %s seconds after outgoing handoffs to layer %s",
                self.layer_ID,
                grace_seconds,
                next_layer_id,
            )
            await asyncio.sleep(grace_seconds)
        finally:
            self._release_handoff_resources()

    def _compute_blocks(self, schedule, handoff_interval):
        return [
            schedule[start : start + handoff_interval]
            for start in range(0, len(schedule), handoff_interval)
        ]

    def _slice_values(self, values, start, end):
        return {
            "commitment": values["commitment"][start:end],
            "proof": values["proof"][start:end],
        }

    def _select_values(self, values, indices):
        return {
            "commitment": [values["commitment"][i] for i in indices],
            "proof": [values["proof"][i] for i in indices],
        }

    def _linear_comb(self, terms, coeffs):
        if not HAS_LINEAR_COMB:
            raise RuntimeError(
                "pyCircuitLinearComb is missing; rebuild kzg_ped_out.so first"
            )
        payload = json.dumps({"terms": terms}).encode("utf-8")
        coeff_payload = json.dumps([str(c) for c in coeffs]).encode("utf-8")
        result = lib.pyCircuitLinearComb(payload, coeff_payload)
        if isinstance(result, bytes):
            result = result.decode("utf-8")
        decoded = json.loads(result)
        if "error" in decoded:
            raise RuntimeError(decoded["error"])
        return decoded

    def _place_pair_outputs(self, k, pairs, o1, o2):
        commitments = [None] * k
        proofs = [None] * k
        for idx, (left, right) in enumerate(pairs):
            commitments[left] = o1["commitment"][idx]
            proofs[left] = o1["proof"][idx]
            commitments[right] = o2["commitment"][idx]
            proofs[right] = o2["proof"][idx]
        return {"commitment": commitments, "proof": proofs}

    def _handoff_ack_tag(self, kind, layer_id):
        return ADMPCMsgType.TRANS + "_SHUF_ACK_" + kind + "_" + str(layer_id)

    def _send_handoff_ack(self, kind):
        if self.layer_ID == 0:
            return
        acktag = self._handoff_ack_tag(kind, self.layer_ID)
        acksend = self.get_send(acktag)
        prev_base = (self.layer_ID - 1) * self.n
        payload = {"kind": kind, "layer": self.layer_ID, "sender": self.my_id}
        for dest in range(self.n):
            acksend(prev_base + dest, payload)
        logging.info(
            "layer ID: %s sent %s handoff ack to layer %s",
            self.layer_ID,
            kind,
            self.layer_ID - 1,
        )

    async def _wait_handoff_ack(self, kind, next_layer_id):
        acktag = self._handoff_ack_tag(kind, next_layer_id)
        ackrecv = self.subscribe_recv(acktag)
        needed = self.n - self.t
        seen = set()
        start = time.time()
        while len(seen) < needed:
            sender, _ = await ackrecv()
            if isinstance(sender, int):
                sender_layer = sender // self.n
                sender_id = sender % self.n
                if sender_layer != next_layer_id:
                    continue
                seen.add(sender_id)
            else:
                seen.add(sender)
        logging.info(
            "layer ID: %s received %s/%s %s handoff acks from layer %s in %s",
            self.layer_ID,
            len(seen),
            needed,
            kind,
            next_layer_id,
            time.time() - start,
        )

    async def _share_client_inputs_to_next_layer(self, k):
        if self.next_pks is None:
            raise RuntimeError("layer 0 has no next committee public keys")

        inputs_per_dealer = (k + self.n - 1) // self.n
        values = lib.pySampleSecret(inputs_per_dealer)
        start = time.time()

        acsstag = ADMPCMsgType.ACSS + "_SHUF_INPUT_" + str(self.layer_ID + 1)
        acsssend = self.get_send(acsstag)
        acssrecv = self.subscribe_recv(acsstag)
        acss = ACSS_Pre(
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
        self._retain_handoff_resource(acss)
        task = asyncio.create_task(acss.avss(0, coms=None, values=values))
        await task

        elapsed = time.time() - start
        logging.info(
            "layer ID: %s shuffle_input_pre_time: %s, inputs_per_dealer: %s",
            self.layer_ID,
            elapsed,
            inputs_per_dealer,
        )

    async def _receive_client_inputs(self, k):
        inputs_per_dealer = (k + self.n - 1) // self.n
        start = time.time()

        acsstag = ADMPCMsgType.ACSS + "_SHUF_INPUT_" + str(self.layer_ID)
        acsssend = self.get_send(acsstag)
        acssrecv = self.subscribe_recv(acsstag)
        acss = ACSS_Foll(
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
        tasks = [
            asyncio.create_task(
                acss.avss(0, inputs_per_dealer, coms=None, dealer_id=dealer_id)
            )
            for dealer_id in range(self.n)
        ]

        outputs = {}
        while True:
            try:
                dealer, _, shares, commitments = await acss.output_queue.get()
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.exception(
                    "layer ID: %s failed receiving shuffle inputs", self.layer_ID
                )
                continue

            outputs[dealer] = {"shares": shares, "commits": commitments}
            if len(outputs) == self.n:
                break

        merged_shares = []
        merged_commits = []
        for dealer_id in range(self.n):
            merged_shares.extend(json.loads(outputs[dealer_id]["shares"].decode("utf-8")))
            merged_commits.extend(json.loads(outputs[dealer_id]["commits"].decode("utf-8")))

        for task in tasks:
            if not task.done():
                task.cancel()

        elapsed = time.time() - start
        logging.info(
            "layer ID: %s shuffle_input_foll_time: %s, inputs: %s",
            self.layer_ID,
            elapsed,
            k,
        )
        return {"commitment": merged_commits[:k], "proof": merged_shares[:k]}

    async def _share_bits_to_next_layer(self, bit_num):
        randtag = ADMPCMsgType.GENRAND + "_SHUF_BITS_" + str(self.layer_ID + 1)
        randsend = self.get_send(randtag)
        randrecv = self.subscribe_recv(randtag)
        rand_pre = BatchRandBit_Pre(
            self.next_pks,
            self.private_key,
            self.n,
            self.t,
            self.srs,
            self.my_id,
            randsend,
            randrecv,
            bit_num,
            self,
        )
        self._retain_handoff_resource(rand_pre)
        await rand_pre.run_randbit()

    async def _receive_bits(self, bit_num):
        randtag = ADMPCMsgType.GENRAND + "_SHUF_BITS_" + str(self.layer_ID)
        randsend = self.get_send(randtag)
        randrecv = self.subscribe_recv(randtag)
        rand_foll = BatchRandBit_Foll(
            self.public_keys,
            self.private_key,
            self.n,
            self.t,
            self.srs,
            self.my_id,
            randsend,
            randrecv,
            bit_num,
            self,
        )
        try:
            bits = await rand_foll.run_randbit()
        finally:
            rand_foll.kill()
        return bits

    async def _send_state_to_next_layer(self, values, k):
        start = time.time()
        transtag = ADMPCMsgType.TRANS + "_SHUF_STATE_" + str(self.layer_ID + 1)
        transsend = self.get_send(transtag)
        transrecv = self.subscribe_recv(transtag)
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
            k,
            values,
            mpc_instance=self,
        )
        self._retain_handoff_resource(trans_pre)
        await trans_pre.run_transfer()
        elapsed = time.time() - start
        logging.info("layer ID: %s aggtrans_pre_time: %s", self.layer_ID, elapsed)

    async def _receive_state_from_prev_layer(self, k):
        start = time.time()
        transtag = ADMPCMsgType.TRANS + "_SHUF_STATE_" + str(self.layer_ID)
        transsend = self.get_send(transtag)
        transrecv = self.subscribe_recv(transtag)
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
            k,
            mpc_instance=self,
        )
        try:
            values = await trans_foll.run_transfer(k)
        except BaseException:
            trans_foll.kill()
            raise
        # Do not tear down the selected ACSS/AVID responders at local
        # AggTrans output.  Retain them until the layer's existing handoff
        # grace/cleanup point, without adding that drain to AggTrans latency.
        self._retain_handoff_resource(trans_foll)
        elapsed = time.time() - start
        logging.info("layer ID: %s aggtrans_foll_time: %s", self.layer_ID, elapsed)
        return values

    async def _run_local_batchmul(self, left_inputs, right_inputs, batchsize):
        start = time.time()
        if not hasattr(self, "_local_mul_counter"):
            self._local_mul_counter = 0
        op_id = self._local_mul_counter
        self._local_mul_counter += 1

        multag = ADMPCMsgType.MUL + "_SHUF_LOCAL_" + str(self.layer_ID) + "_" + str(op_id)
        mulsend = self.get_send(multag)
        mulrecv = self.subscribe_recv(multag)
        mul = BatchMulLocal(
            self.public_keys,
            self.private_key,
            self.pkbls,
            self.skbls,
            self.n,
            self.t,
            self.srs,
            self.my_id,
            mulsend,
            mulrecv,
            batchsize,
            self,
        )
        try:
            outputs = await mul.run_multiply(left_inputs, right_inputs)
        finally:
            mul.kill()
        elapsed = time.time() - start
        logging.info("layer ID: %s local_batchmul_time: %s", self.layer_ID, elapsed)
        return outputs

    async def _run_switch_layer(self, state, bits, pairs, k):
        linear_start = time.time()
        left_indices = [left for left, _ in pairs]
        right_indices = [right for _, right in pairs]
        i1 = self._select_values(state, left_indices)
        i2 = self._select_values(state, right_indices)

        s = self._linear_comb([i1, i2], [1, 1])
        d = self._linear_comb([i1, i2], [1, -1])
        linear_time = time.time() - linear_start
        logging.info("layer ID: %s switch_linear_pre_time: %s", self.layer_ID, linear_time)

        signed_diff = await self._run_local_batchmul(bits, d, len(pairs))

        linear_start = time.time()
        o1 = self._linear_comb([s, signed_diff], [INV_TWO, INV_TWO])
        o2 = self._linear_comb([s, signed_diff], [INV_TWO, -INV_TWO])
        next_state = self._place_pair_outputs(k, pairs, o1, o2)
        linear_time = time.time() - linear_start
        logging.info("layer ID: %s switch_linear_post_time: %s", self.layer_ID, linear_time)
        return next_state

    async def _run_switch_block(self, state, bits, schedule_slice, k):
        bits_per_layer = k // 2
        for offset, pairs in enumerate(schedule_slice):
            start = offset * bits_per_layer
            end = start + bits_per_layer
            bits_for_layer = self._slice_values(bits, start, end)
            state = await self._run_switch_layer(state, bits_for_layer, pairs, k)
        return state

    async def _reconstruct_final_state(self, state):
        raw_proofs = state["proof"]
        claimed_values = [int(entry["ClaimedValue"]) for entry in raw_proofs]
        output_values = await self.reconstruct_values(claimed_values)
        logging.info(
            "layer ID: %s reconstructed shuffle output length: %s",
            self.layer_ID,
            len(output_values),
        )

    async def run_admpc(self, start_time):
        layer_time = time.time()
        handoff_keepalive_layer = None
        logging.info("[Layer %s] Reached shuffle/mixing checkpoint", self.layer_ID)

        try:
            k = int(self.admpc_control_instance.total_cm)
            mode = self._shuffle_mode()
            schedule = build_butterfly_schedule(k, mode)
            switch_layers = len(schedule)
            bit_num = k // 2
            handoff_interval = self._handoff_interval(switch_layers)
            blocks = self._compute_blocks(schedule, handoff_interval)
            compute_blocks = len(blocks)
            expected_layers = compute_blocks + 2

            if self.admpc_control_instance.layer_num != expected_layers:
                logging.error(
                    "shuffle config mismatch: k=%s, mode=%s, handoff_interval=%s expects layers=%s, got layers=%s",
                    k,
                    mode,
                    handoff_interval,
                    expected_layers,
                    self.admpc_control_instance.layer_num,
                )
                return

            logging.info(
                "shuffle config: k=%s, mode=%s, switch_layers=%s, handoff_interval=%s, compute_blocks=%s, bit_num_per_layer=%s",
                k,
                mode,
                switch_layers,
                handoff_interval,
                compute_blocks,
                bit_num,
            )

            if self.layer_ID == 0:
                first_block_bits = len(blocks[0]) * bit_num
                await asyncio.gather(
                    self._share_client_inputs_to_next_layer(k),
                    self._share_bits_to_next_layer(first_block_bits),
                )
                handoff_keepalive_layer = self.layer_ID + 1

            elif 1 <= self.layer_ID <= compute_blocks:
                block_idx = self.layer_ID - 1
                schedule_slice = blocks[block_idx]
                bits_for_block = len(schedule_slice) * bit_num

                if self.layer_ID == 1:
                    state = await self._receive_client_inputs(k)
                else:
                    state = await self._receive_state_from_prev_layer(k)
                bits = await self._receive_bits(bits_for_block)

                switch_start = time.time()
                next_state = await self._run_switch_block(state, bits, schedule_slice, k)
                switch_time = time.time() - switch_start
                logging.info(
                    "layer ID: %s switch_block_time: %s, switch_layers: %s, switch_gates: %s",
                    self.layer_ID,
                    switch_time,
                    len(schedule_slice),
                    len(schedule_slice) * bit_num,
                )

                await self._send_state_to_next_layer(next_state, k)
                if block_idx + 1 < compute_blocks:
                    next_block_bits = len(blocks[block_idx + 1]) * bit_num
                    await self._share_bits_to_next_layer(next_block_bits)
                handoff_keepalive_layer = self.layer_ID + 1

            elif self.layer_ID == compute_blocks + 1:
                final_state = await self._receive_state_from_prev_layer(k)
                reconstruct_start = time.time()
                await self._reconstruct_final_state(final_state)
                trusted_time = time.time() - reconstruct_start
                logging.info(
                    "layer ID: %s trusted_verification_time: %s",
                    self.layer_ID,
                    trusted_time,
                )

        finally:
            elapsed = time.time() - layer_time
            logging.info("layer ID: %s shuffle_layer_time: %s", self.layer_ID, elapsed)
            if handoff_keepalive_layer is not None:
                await self._keep_sender_alive_after_handoff(handoff_keepalive_layer)
            else:
                self._release_handoff_resources()
            logging.info("Shuffle layer complete; waiting for runner shutdown")
            await asyncio.sleep(2)
