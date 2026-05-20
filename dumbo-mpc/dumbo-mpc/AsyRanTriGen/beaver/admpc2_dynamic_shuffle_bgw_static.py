import asyncio
import logging
import time

from beaver.admpc2_dynamic_shuffle import ADMPC_Dynamic as _ShuffleADMPCDynamic
from beaver.bgw_multiplication import BGWReduction
from beaver.shuffle_network import build_butterfly_schedule


class ADMPC_Dynamic(_ShuffleADMPCDynamic):
    """Static shuffle baseline that evaluates multiplication with Dumbo-MPC BGW."""

    async def _run_local_batchmul(self, left_inputs, right_inputs, batchsize):
        start = time.time()
        if not hasattr(self, "_local_bgw_counter"):
            self._local_bgw_counter = 0
        op_id = self._local_bgw_counter
        self._local_bgw_counter += 1

        bgwtag = "M_SHUF_BGW_STATIC_" + str(self.layer_ID) + "_" + str(op_id)
        bgwsend = self.get_send(bgwtag)
        bgwrecv = self.subscribe_recv(bgwtag)
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
            batchsize,
            self,
        )
        try:
            outputs = await bgw.run_multiply(left_inputs, right_inputs)
        finally:
            bgw.kill()
        elapsed = time.time() - start
        logging.info("layer ID: %s bgw_static_mul_time: %s", self.layer_ID, elapsed)
        return outputs

    async def run_admpc(self, start_time):
        layer_time = time.time()
        handoff_keepalive_layer = None
        logging.info("[Layer %s] Reached shuffle BGW-static checkpoint", self.layer_ID)

        try:
            k = int(self.admpc_control_instance.total_cm)
            mode = self._shuffle_mode()
            schedule = build_butterfly_schedule(k, mode)
            switch_layers = len(schedule)
            bit_num = k // 2
            bits_for_circuit = switch_layers * bit_num
            expected_layers = 3

            if self.admpc_control_instance.layer_num != expected_layers:
                logging.error(
                    "shuffle BGW-static config mismatch: k=%s, mode=%s expects layers=%s, got layers=%s",
                    k,
                    mode,
                    expected_layers,
                    self.admpc_control_instance.layer_num,
                )
                return

            logging.info(
                "shuffle BGW-static config: k=%s, mode=%s, switch_layers=%s, bits=%s",
                k,
                mode,
                switch_layers,
                bits_for_circuit,
            )

            if self.layer_ID == 0:
                await asyncio.gather(
                    self._share_client_inputs_to_next_layer(k),
                    self._share_bits_to_next_layer(bits_for_circuit),
                )
                handoff_keepalive_layer = self.layer_ID + 1

            elif self.layer_ID == 1:
                state_task = asyncio.create_task(self._receive_client_inputs(k))
                bits_task = asyncio.create_task(self._receive_bits(bits_for_circuit))
                state, bits = await asyncio.gather(state_task, bits_task)

                switch_start = time.time()
                next_state = await self._run_switch_block(state, bits, schedule, k)
                switch_time = time.time() - switch_start
                logging.info(
                    "layer ID: %s bgw_static_switch_time: %s, switch_layers: %s, switch_gates: %s",
                    self.layer_ID,
                    switch_time,
                    switch_layers,
                    bits_for_circuit,
                )

                await self._send_state_to_next_layer(next_state, k)
                handoff_keepalive_layer = self.layer_ID + 1

            elif self.layer_ID == 2:
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
            logging.info("layer ID: %s shuffle_bgw_static_layer_time: %s", self.layer_ID, elapsed)
            if handoff_keepalive_layer is not None:
                await self._keep_sender_alive_after_handoff(handoff_keepalive_layer)
            else:
                self._release_handoff_resources()
            logging.info("Shuffle BGW-static layer complete; waiting for runner shutdown")
            await asyncio.sleep(5)
