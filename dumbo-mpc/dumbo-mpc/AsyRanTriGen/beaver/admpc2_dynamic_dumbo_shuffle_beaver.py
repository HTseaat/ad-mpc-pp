import asyncio
import json
import logging
import os
import time
from ctypes import c_char_p, c_int

from beaver.admpc2_dynamic_shuffle import ADMPC_Dynamic as _ShuffleADMPCDynamic
from beaver.admpc2_dynamic_shuffle import lib
from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.hbacss import Hbacss1
from beaver.shuffle_network import build_butterfly_schedule
from beaver.utils.misc import subscribe_recv, wrap_send
from optimizedhbmpc.elliptic_curve import Subgroup
from optimizedhbmpc.field import GF
from optimizedhbmpc.mpc import Mpc


logger = logging.getLogger(__name__)

lib.VMmatrixGen.argtypes = [c_int]
lib.VMmatrixGen.restype = c_char_p
lib.pyRandomShareCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyRandomShareCompute.restype = c_char_p
lib.pyTriplesCompute.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyTriplesCompute.restype = c_char_p


class DumboShuffleBeaverMsg:
    OUTER = "DSB"
    RAND_ACSS = "DSB_RAND_ACSS"
    RAND_ACS = "DSB_RAND_ACS"
    REDUCE_ACSS = "DSB_REDUCE_ACSS"
    REDUCE_ACS = "DSB_REDUCE_ACS"
    OPEN = "DSB_OPEN_"
    OUTPUT = "DSB_OUTPUT_"


class ADMPC_Dynamic(_ShuffleADMPCDynamic):
    """Three-committee shuffle baseline using Dumbo offline triples.

    Layer 0 acts as clients and shares inputs plus selector bits to layer 1.
    Layer 1 generates Beaver triples with Dumbo-MPC's original AsyRanTriGen
    path, evaluates the full switching network online, and opens the output.
    Layer 2 is retained as the output/client committee shape for apples-to-
    apples comparison with shuffle-bgw-static. Layer 1 sends the public opened
    output to layer 2 so the output committee's layer time reflects end-to-end
    completion without adding an AggTrans handoff.
    """

    def _bits_needed(self, schedule):
        return sum(len(pairs) for pairs in schedule)

    def _local_send_recv(self, tag):
        if not hasattr(self, "_dsb_subscribe_recv"):
            outer_send = self.get_send(DumboShuffleBeaverMsg.OUTER)
            outer_recv = self.subscribe_recv(DumboShuffleBeaverMsg.OUTER)
            layer_base = self.layer_ID * self.n

            def local_send(dest, message):
                outer_send(layer_base + dest, message)

            async def local_recv():
                sender, message = await outer_recv()
                return sender % self.n, message

            self._dsb_subscribe_recv_task, self._dsb_subscribe_recv = subscribe_recv(
                local_recv
            )

        return wrap_send(tag, self._dsb_local_send), self._dsb_subscribe_recv(tag)

    def _dsb_local_send(self, dest, message):
        outer_send = self.get_send(DumboShuffleBeaverMsg.OUTER)
        layer_base = self.layer_ID * self.n
        outer_send(layer_base + dest, message)

    async def _run_hbacss_acs(self, tag_prefix, values, mode, leader):
        acsssend, acssrecv = self._local_send_recv(tag_prefix + "_ACSS")
        coms = None
        if mode == "avss_with_proof":
            decoded = json.loads(values.decode("utf-8"))
            coms = json.dumps(decoded["commitment"]).encode("utf-8")

        acss = Hbacss1(
            self.public_keys,
            self.private_key,
            self.srs,
            self.n,
            self.t,
            self.my_id,
            acsssend,
            acssrecv,
            mode,
        )
        if not hasattr(self, "_dsb_acss_instances"):
            self._dsb_acss_instances = []
        if not hasattr(self, "_dsb_tasks"):
            self._dsb_tasks = []
        self._dsb_acss_instances.append(acss)

        tasks = [None] * self.n
        for dealer_id in range(self.n):
            if dealer_id == self.my_id:
                tasks[dealer_id] = asyncio.create_task(
                    acss.avss(0, coms=coms, values=values)
                )
            else:
                tasks[dealer_id] = asyncio.create_task(
                    acss.avss(0, coms=coms, dealer_id=dealer_id)
                )
        self._dsb_tasks.extend(tasks)

        outputs = {}
        signal = asyncio.Event()

        async def collect_outputs():
            while True:
                try:
                    dealer, _, shares, commitments = await acss.output_queue.get()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "[%d] Dumbo shuffle ACSS output failed for %s",
                        self.my_id,
                        tag_prefix,
                    )
                    continue
                outputs[dealer] = {"shares": shares, "commits": commitments}
                if len(outputs) >= self.n - self.t:
                    signal.set()
                if len(outputs) == self.n:
                    return

        collect_task = asyncio.create_task(collect_outputs())
        self._dsb_tasks.append(collect_task)

        await signal.wait()
        signal.clear()
        proposal = list(outputs.keys())

        acssend, acsrecv = self._local_send_recv(tag_prefix + "_ACS")
        acs = OptimalCommonSet(
            tag_prefix + "_ACS",
            self.my_id,
            self.n,
            self.t,
            leader,
            proposal,
            self.pkbls,
            self.skbls,
            acssend,
            acsrecv,
            outputs,
            signal,
        )
        try:
            common = sorted(list(await acs.handle_message()))
        finally:
            try:
                acs.subscribe_recv_task.cancel()
            except Exception:
                pass

        common_set = set(common)
        while not common_set.issubset(outputs.keys()):
            signal.clear()
            if common_set.issubset(outputs.keys()):
                break
            await signal.wait()

        logger.info(
            "layer ID: %s %s common=%s",
            self.layer_ID,
            tag_prefix,
            common,
        )
        return common, outputs

    def _gen_random_shares(self, matrix, common, outputs):
        serialized_common = json.dumps(sorted(list(common))).encode("utf-8")
        commitments = [None] * self.n
        shares = [None] * self.n
        for dealer_id in common:
            commitments[dealer_id] = json.loads(outputs[dealer_id]["commits"].decode("utf-8"))
            shares[dealer_id] = json.loads(outputs[dealer_id]["shares"].decode("utf-8"))

        return lib.pyRandomShareCompute(
            matrix,
            serialized_common,
            json.dumps(commitments).encode("utf-8"),
            json.dumps(shares).encode("utf-8"),
            self.t,
        )

    def _gen_triples(self, common, outputs, sharesproofs_ab):
        serialized_common = json.dumps(sorted(list(common))).encode("utf-8")
        commitments = [None] * self.n
        shares = [None] * self.n
        for dealer_id in common:
            commitments[dealer_id] = json.loads(outputs[dealer_id]["commits"].decode("utf-8"))
            shares[dealer_id] = json.loads(outputs[dealer_id]["shares"].decode("utf-8"))

        decoded_ab = json.loads(sharesproofs_ab.decode("utf-8"))
        serialized_share_ab = json.dumps(decoded_ab["proof"]).encode("utf-8")
        return lib.pyTriplesCompute(
            serialized_common,
            serialized_share_ab,
            json.dumps(shares).encode("utf-8"),
            json.dumps(commitments).encode("utf-8"),
        )

    async def _generate_dumbo_triples(self, triple_count):
        if triple_count <= 0:
            return {"A": [], "B": [], "C": []}

        if hasattr(lib, "pySetN"):
            lib.pySetN(self.n)
        matrix = lib.VMmatrixGen(self.t)
        start = time.time()
        unbatched_verify = os.getenv("BGW_UNBATCHED_VERIFY") == "1"
        random_batch_size = (2 * triple_count + self.t) // (self.t + 1)
        generated_capacity = ((self.t + 1) * random_batch_size) // 2
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_triple_generation_start: requested_triples=%s, random_batch_size=%s, generated_capacity=%s, bgw_unbatched_verify=%s",
            self.layer_ID,
            triple_count,
            random_batch_size,
            generated_capacity,
            int(unbatched_verify),
        )

        values = lib.pySampleSecret(random_batch_size)
        random_acss_acs_start = time.time()
        random_common, random_outputs = await self._run_hbacss_acs(
            DumboShuffleBeaverMsg.RAND_ACSS,
            values,
            "avss_without_proof",
            leader=1 if self.n > 1 else 0,
        )
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_random_acss_acs_time: %s, random_batch_size=%s, common_size=%s",
            self.layer_ID,
            time.time() - random_acss_acs_start,
            random_batch_size,
            len(random_common),
        )
        random_compute_start = time.time()
        randomshares_proofs = self._gen_random_shares(
            matrix,
            random_common,
            random_outputs,
        )
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_random_share_compute_time: %s, random_batch_size=%s, generated_random_shares=%s",
            self.layer_ID,
            time.time() - random_compute_start,
            random_batch_size,
            (self.t + 1) * random_batch_size,
        )

        reduce_acss_acs_start = time.time()
        reduce_common, reduce_outputs = await self._run_hbacss_acs(
            DumboShuffleBeaverMsg.REDUCE_ACSS,
            randomshares_proofs,
            "avss_with_proof",
            leader=2 if self.n > 2 else 0,
        )
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_reduce_acss_acs_time: %s, requested_triples=%s, common_size=%s",
            self.layer_ID,
            time.time() - reduce_acss_acs_start,
            triple_count,
            len(reduce_common),
        )
        triples_compute_start = time.time()
        serialized_triples = self._gen_triples(
            reduce_common,
            reduce_outputs,
            randomshares_proofs,
        )
        triples = self._decode_triples(serialized_triples, triple_count)
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_triples_compute_time: %s, requested_triples=%s",
            self.layer_ID,
            time.time() - triples_compute_start,
            triple_count,
        )
        elapsed = time.time() - start
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_offline_time: %s, requested_triples=%s, random_batch_size=%s, generated_capacity=%s",
            self.layer_ID,
            elapsed,
            triple_count,
            random_batch_size,
            generated_capacity,
        )
        return triples

    def _decode_triples(self, serialized_triples, count):
        obj = json.loads(serialized_triples.decode("utf-8"))

        def to_ints(values):
            out = []
            for value in values:
                if isinstance(value, int):
                    out.append(value)
                elif isinstance(value, str):
                    out.append(int(value, 16) if value.lower().startswith("0x") else int(value))
                else:
                    out.append(int(value))
            return out

        if all(key in obj for key in ("A", "B", "C")):
            return {
                "A": to_ints(obj["A"])[:count],
                "B": to_ints(obj["B"])[:count],
                "C": to_ints(obj["C"])[:count],
            }

        def pick(container):
            if isinstance(container, list):
                return container[self.my_id]
            if isinstance(container, dict):
                key = str(self.my_id) if str(self.my_id) in container else self.my_id
                return container[key]
            raise ValueError("Unexpected triples encoding container")

        return {
            "A": to_ints(pick(obj.get("a", obj.get("A", []))))[:count],
            "B": to_ints(pick(obj.get("b", obj.get("B", []))))[:count],
            "C": to_ints(pick(obj.get("c", obj.get("C", []))))[:count],
        }

    def _proofs_to_field(self, values):
        field = GF(Subgroup.BLS12_381)
        result = []
        for entry in values["proof"]:
            if isinstance(entry, dict) and "ClaimedValue" in entry:
                raw = entry["ClaimedValue"]
            else:
                raw = entry
            result.append(field(int(raw)))
        return result

    async def _open_share_array(self, tag_suffix, shares):
        send, recv = self._local_send_recv(DumboShuffleBeaverMsg.OPEN + tag_suffix)

        async def prog(ctx):
            return await ctx.ShareArray(shares, self.t).open()

        os.makedirs("sharedata_test", exist_ok=True)
        ctx = Mpc(
            "mpc:dumbo-shuffle-beaver:" + tag_suffix,
            self.n,
            self.t,
            self.my_id,
            send,
            recv,
            prog,
            {},
        )
        return await ctx._run()

    def _encode_public_outputs(self, output_values):
        encoded = []
        for value in output_values:
            try:
                encoded.append(str(int(value)))
            except TypeError:
                encoded.append(str(value))
        return encoded

    async def _send_public_output_to_next_layer(self, output_values):
        if self.layer_ID + 1 >= self.admpc_control_instance.layer_num:
            return

        tag = DumboShuffleBeaverMsg.OUTPUT + str(self.layer_ID + 1)
        send = self.get_send(tag)
        next_base = (self.layer_ID + 1) * self.n
        payload = {
            "layer": self.layer_ID,
            "sender": self.my_id,
            "outputs": self._encode_public_outputs(output_values),
        }
        start = time.time()
        for dest in range(self.n):
            send(next_base + dest, payload)
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_output_send_time: %s, outputs=%s",
            self.layer_ID,
            time.time() - start,
            len(output_values),
        )

    async def _receive_public_output_from_prev_layer(self, k):
        tag = DumboShuffleBeaverMsg.OUTPUT + str(self.layer_ID)
        recv = self.subscribe_recv(tag)
        prev_layer = self.layer_ID - 1
        needed = self.n - self.t
        outputs_by_sender = {}
        start = time.time()

        while len(outputs_by_sender) < needed:
            sender, payload = await recv()
            if not isinstance(sender, int):
                continue
            sender_layer = sender // self.n
            sender_id = sender % self.n
            if sender_layer != prev_layer:
                continue
            if not isinstance(payload, dict):
                continue
            outputs = payload.get("outputs")
            if not isinstance(outputs, list) or len(outputs) != k:
                logger.warning(
                    "layer ID: %s ignored malformed dumbo shuffle Beaver output from sender %s",
                    self.layer_ID,
                    sender_id,
                )
                continue
            outputs_by_sender[sender_id] = outputs

        elapsed = time.time() - start
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_output_recv_time: %s, senders=%s, outputs=%s",
            self.layer_ID,
            elapsed,
            len(outputs_by_sender),
            k,
        )
        first_sender = sorted(outputs_by_sender.keys())[0]
        return outputs_by_sender[first_sender]

    async def _run_switch_layer_with_triples(
        self,
        state,
        bits,
        triples,
        pairs,
        layer_idx,
        triple_cursor,
        bit_cursor,
    ):
        field = GF(Subgroup.BLS12_381)
        width = len(pairs)
        a_slice = [field(v) for v in triples["A"][triple_cursor : triple_cursor + width]]
        b_slice = [field(v) for v in triples["B"][triple_cursor : triple_cursor + width]]
        c_slice = [field(v) for v in triples["C"][triple_cursor : triple_cursor + width]]
        bit_slice = bits[bit_cursor : bit_cursor + width]

        if min(len(a_slice), len(b_slice), len(c_slice), len(bit_slice)) < width:
            raise RuntimeError(
                "Not enough triples or selector bits for shuffle layer "
                f"{layer_idx}: need={width}"
            )

        diffs = [state[right] - state[left] for left, right in pairs]
        gammas = [bit_slice[i] - a_slice[i] for i in range(width)]
        epsilons = [diffs[i] - b_slice[i] for i in range(width)]
        opened = await self._open_share_array(
            "L" + str(layer_idx),
            gammas + epsilons,
        )
        gamma_pub = opened[:width]
        epsilon_pub = opened[width:]

        products = [
            c_slice[i]
            + gamma_pub[i] * b_slice[i]
            + epsilon_pub[i] * a_slice[i]
            + gamma_pub[i] * epsilon_pub[i]
            for i in range(width)
        ]
        next_state = list(state)
        for idx, (left, right) in enumerate(pairs):
            next_state[left] = state[left] + products[idx]
            next_state[right] = state[right] - products[idx]

        return next_state, triple_cursor + width, bit_cursor + width

    async def _run_shuffle_online(self, state_values, bit_values, triples, schedule):
        state = self._proofs_to_field(state_values)
        bits = self._proofs_to_field(bit_values)
        triple_cursor = 0
        bit_cursor = 0

        online_start = time.time()
        for layer_idx, pairs in enumerate(schedule):
            layer_start = time.time()
            state, triple_cursor, bit_cursor = await self._run_switch_layer_with_triples(
                state,
                bits,
                triples,
                pairs,
                layer_idx,
                triple_cursor,
                bit_cursor,
            )
            logger.info(
                "layer ID: %s dumbo_shuffle_beaver_switch_layer_time: %s, switch_layer=%s, gates=%s",
                self.layer_ID,
                time.time() - layer_start,
                layer_idx,
                len(pairs),
            )

        final_start = time.time()
        output_values = await self._open_share_array("FINAL", state)
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_final_open_time: %s, outputs=%s",
            self.layer_ID,
            time.time() - final_start,
            len(output_values),
        )
        logger.info(
            "layer ID: %s dumbo_shuffle_beaver_online_time: %s, gates=%s, bits=%s",
            self.layer_ID,
            time.time() - online_start,
            triple_cursor,
            bit_cursor,
        )
        return output_values

    def _cleanup_dsb_resources(self):
        task = getattr(self, "_dsb_subscribe_recv_task", None)
        if task is not None and not task.done():
            task.cancel()
        for task in getattr(self, "_dsb_tasks", []):
            if task is not None and not task.done():
                task.cancel()
        for acss in getattr(self, "_dsb_acss_instances", []):
            try:
                acss.kill()
            except Exception:
                logger.debug(
                    "layer ID: %s failed cleaning dumbo shuffle ACSS",
                    self.layer_ID,
                    exc_info=True,
                )

    async def run_admpc(self, start_time):
        layer_time = time.time()
        handoff_keepalive_layer = None
        logger.info("[Layer %s] Reached dumbo-shuffle-beaver checkpoint", self.layer_ID)

        try:
            k = int(self.admpc_control_instance.total_cm)
            mode = self._shuffle_mode()
            schedule = build_butterfly_schedule(k, mode)
            switch_layers = len(schedule)
            bits_needed = self._bits_needed(schedule)
            expected_layers = 3

            if self.admpc_control_instance.layer_num != expected_layers:
                logger.error(
                    "dumbo-shuffle-beaver config mismatch: k=%s, mode=%s expects layers=%s, got layers=%s",
                    k,
                    mode,
                    expected_layers,
                    self.admpc_control_instance.layer_num,
                )
                return

            logger.info(
                "dumbo-shuffle-beaver config: k=%s, mode=%s, switch_layers=%s, triples=%s, bits=%s",
                k,
                mode,
                switch_layers,
                bits_needed,
                bits_needed,
            )

            if self.layer_ID == 0:
                handoff_start = time.time()
                await asyncio.gather(
                    self._share_client_inputs_to_next_layer(k),
                    self._share_bits_to_next_layer(bits_needed),
                )
                logger.info(
                    "layer ID: %s dumbo_shuffle_beaver_client_handoff_time: %s, inputs=%s, random_bits=%s",
                    self.layer_ID,
                    time.time() - handoff_start,
                    k,
                    bits_needed,
                )
                handoff_keepalive_layer = self.layer_ID + 1

            elif self.layer_ID == 1:
                receive_handoff_start = time.time()
                state_task = asyncio.create_task(self._receive_client_inputs(k))
                bits_task = asyncio.create_task(self._receive_bits(bits_needed))
                state, bits = await asyncio.gather(state_task, bits_task)
                logger.info(
                    "layer ID: %s dumbo_shuffle_beaver_server_receive_handoff_time: %s, inputs=%s, random_bits=%s",
                    self.layer_ID,
                    time.time() - receive_handoff_start,
                    k,
                    bits_needed,
                )
                triples = await self._generate_dumbo_triples(bits_needed)
                output_values = await self._run_shuffle_online(
                    state,
                    bits,
                    triples,
                    schedule,
                )
                logger.info(
                    "layer ID: %s Dumbo shuffle Beaver output reconstructed length: %s",
                    self.layer_ID,
                    len(output_values),
                )
                await self._send_public_output_to_next_layer(output_values)

            elif self.layer_ID == 2:
                output_values = await self._receive_public_output_from_prev_layer(k)
                logger.info(
                    "layer ID: %s Dumbo shuffle Beaver output received length: %s",
                    self.layer_ID,
                    len(output_values),
                )

        finally:
            elapsed = time.time() - layer_time
            logger.info(
                "layer ID: %s dumbo_shuffle_beaver_layer_time: %s",
                self.layer_ID,
                elapsed,
            )
            if handoff_keepalive_layer is not None:
                await self._keep_sender_alive_after_handoff(handoff_keepalive_layer)
            else:
                self._release_handoff_resources()
            self._cleanup_dsb_resources()
            logger.info("Dumbo shuffle Beaver layer complete; waiting for runner shutdown")
            await asyncio.sleep(2)
