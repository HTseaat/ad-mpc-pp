"""AD-MPC implementation of the Figure 12 full-dynamic shuffle circuit."""

import asyncio
import hashlib
import json
import time
from math import ceil

from adkg.acss import ACSS_Foll, ACSS_Pre
from adkg.admpc_dynamic import ADMPC_Dynamic
from adkg.aprep import APREP_Foll, APREP_Pre
from adkg.bundle import (
    Bundle_Foll,
    Bundle_Pre,
    batchbundle_batch_count,
)
from adkg.elliptic_curve import Subgroup
from adkg.rand import Rand_Foll, Rand_Pre, batchrand_batch_count
from adkg.shuffle_network import build_butterfly_schedule, validate_switch_layer
from adkg.trans import Trans_Foll, Trans_Pre


FIG12_INPUTS = 128
FIG12_SWITCHES_PER_LAYER = FIG12_INPUTS // 2
RANDBIT_EXTRA_CANDIDATES = 4
HANDOFF_ACK_MARKER = "admpc-shuffle-handoff-v1"
PHASE_TIMING_SCHEMA = "admpc-shuffle-phase-timing-v1"


def randbit_candidate_capacity(t, target_signs=FIG12_SWITCHES_PER_LAYER):
    """Match Continuum's RandBit candidate capacity for a threshold ``t``."""
    if isinstance(t, bool) or not isinstance(t, int) or t < 0:
        raise ValueError("threshold t must be a non-negative integer")
    if isinstance(target_signs, bool) or not isinstance(target_signs, int):
        raise TypeError("target_signs must be an integer")
    if target_signs <= 0:
        raise ValueError("target_signs must be positive")

    values_per_round = t + 1
    target = target_signs + max(RANDBIT_EXTRA_CANDIDATES, values_per_round)
    return ceil(target / values_per_round) * values_per_round


def shuffle_triple_count(t, target_signs=FIG12_SWITCHES_PER_LAYER):
    """Return square triples plus switch triples for one compute committee."""
    return randbit_candidate_capacity(t, target_signs) + target_signs


def split_shuffle_triples(triples, t, target_signs=FIG12_SWITCHES_PER_LAYER):
    """Split an APREP batch into RandBit-square and switch triples."""
    candidate_count = randbit_candidate_capacity(t, target_signs)
    expected = candidate_count + target_signs
    if len(triples) != expected:
        raise ValueError(f"expected {expected} shuffle triples, got {len(triples)}")
    return list(triples[:candidate_count]), list(triples[candidate_count:])


def inputs_per_dealer(k, n):
    """Return the fixed ACSS input batch size for each dealer."""
    if isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        raise ValueError("input width k must be a positive integer")
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise ValueError("committee size n must be a positive integer")
    return ceil(k / n)


def prepare_dealer_inputs(inputs, dealer_id, n, k=None, zero=0):
    """Return one dealer's contiguous, zero-padded input batch."""
    values = list(inputs)
    if k is None:
        k = len(values)
    if len(values) != k:
        raise ValueError(f"expected exactly {k} public inputs, got {len(values)}")
    if not isinstance(dealer_id, int) or dealer_id < 0 or dealer_id >= n:
        raise ValueError(f"dealer_id must be in [0, {n})")

    batch_size = inputs_per_dealer(k, n)
    start = dealer_id * batch_size
    batch = values[start : start + batch_size]
    return batch + [zero] * (batch_size - len(batch))


def _flatten_acss_payload(payload):
    flattened = []

    def visit(value):
        if isinstance(value, (list, tuple)):
            for item in value:
                visit(item)
        else:
            flattened.append(value)

    visit(payload)
    return flattened


def merge_dealer_input_shares(dealer_to_shares, n, k):
    """Merge dealer-ordered ACSS payloads and trim only the final padding."""
    expected_dealers = set(range(n))
    actual_dealers = set(dealer_to_shares)
    if actual_dealers != expected_dealers:
        missing = sorted(expected_dealers - actual_dealers)
        extra = sorted(actual_dealers - expected_dealers)
        raise ValueError(f"input dealer set mismatch: missing={missing}, extra={extra}")

    batch_size = inputs_per_dealer(k, n)
    merged = []
    for dealer_id in range(n):
        shares = _flatten_acss_payload(dealer_to_shares[dealer_id])
        if len(shares) != batch_size:
            raise ValueError(
                f"dealer {dealer_id} supplied {len(shares)} shares, "
                f"expected {batch_size}"
            )
        merged.extend(shares)
    return merged[:k]


class ADMPC_Dynamic_Shuffle(ADMPC_Dynamic):
    """Protocol primitives for one AD-MPC shuffle compute committee."""

    INPUT_WIDTH = FIG12_INPUTS
    SWITCHES_PER_LAYER = FIG12_SWITCHES_PER_LAYER

    def __init__(
        self,
        public_keys,
        private_key,
        g,
        h,
        n,
        t,
        deg,
        my_id,
        send,
        recv,
        pc,
        curve_params,
        matrices,
        total_cm,
        layerID=None,
        admpc_control_instance=None,
        shuffle_k=FIG12_INPUTS,
        shuffle_mode="iterated",
        run_id="admpc-shuffle-local",
        ack_timeout=600.0,
        ack_threshold=None,
    ):
        super().__init__(
            public_keys,
            private_key,
            g,
            h,
            n,
            t,
            deg,
            my_id,
            send,
            recv,
            pc,
            curve_params,
            matrices,
            total_cm,
            layerID=layerID,
            admpc_control_instance=admpc_control_instance,
        )
        self.shuffle_k = shuffle_k
        self.shuffle_mode = shuffle_mode
        self.shuffle_schedule = build_butterfly_schedule(shuffle_k, shuffle_mode)
        self.switch_layers = len(self.shuffle_schedule)
        self.physical_layers = self.switch_layers + 2
        actual_layers = self.admpc_control_instance.layer_num
        if actual_layers != self.physical_layers:
            raise ValueError(
                f"shuffle {shuffle_mode} k={shuffle_k} requires "
                f"{self.physical_layers} physical layers, got {actual_layers}"
            )
        if layerID is None or layerID < 0 or layerID >= self.physical_layers:
            raise ValueError("shuffle layerID is outside the physical layer range")
        try:
            self.ack_timeout = float(ack_timeout)
        except (TypeError, ValueError) as exc:
            raise ValueError("ack_timeout must be a positive number") from exc
        if self.ack_timeout <= 0:
            raise ValueError("ack_timeout must be a positive number")
        if ack_threshold is None:
            ack_threshold = n
        if not isinstance(ack_threshold, int) or not n - t <= ack_threshold <= n:
            raise ValueError(f"ack_threshold must be in [{n - t}, {n}]")
        self.ack_threshold = ack_threshold
        self.run_id = str(run_id)
        if not self.run_id:
            raise ValueError("shuffle run_id must be non-empty")
        self._shuffle_resources = []
        self._last_result = None
        self._run_started_perf = None

    @staticmethod
    def _mod_sqrt(value, modulus=Subgroup.BLS12_381):
        value %= modulus
        if value == 0:
            return 0
        if pow(value, (modulus - 1) // 2, modulus) != 1:
            return None

        q = modulus - 1
        power_of_two = 0
        while q % 2 == 0:
            power_of_two += 1
            q //= 2

        non_residue = 2
        while pow(non_residue, (modulus - 1) // 2, modulus) != modulus - 1:
            non_residue += 1

        m = power_of_two
        c = pow(non_residue, q, modulus)
        t_value = pow(value, q, modulus)
        root = pow(value, (q + 1) // 2, modulus)
        while t_value != 1:
            index = 1
            squared = pow(t_value, 2, modulus)
            while squared != 1:
                index += 1
                if index >= m:
                    return None
                squared = pow(squared, 2, modulus)
            factor = pow(c, 1 << (m - index - 1), modulus)
            m = index
            c = factor * factor % modulus
            t_value = t_value * c % modulus
            root = root * factor % modulus
        return root

    def _register_resource(self, resource):
        self._shuffle_resources.append(resource)
        return resource

    @staticmethod
    def _safe_kill(resource):
        try:
            resource.kill()
        except Exception:
            pass

    def kill(self):
        for resource in reversed(self._shuffle_resources):
            self._safe_kill(resource)
        self._shuffle_resources.clear()
        self._safe_kill(self.rec)
        if getattr(self, "subscribe_recv_task", None) is not None:
            self.subscribe_recv_task.cancel()

    def _new_phase_timing(self):
        return {"schema": PHASE_TIMING_SCHEMA, "phases": {}}

    async def _measure_phase(self, timing, name, awaitable):
        if self._run_started_perf is None:
            raise RuntimeError("shuffle phase timer started before run_admpc")
        started = time.perf_counter()
        try:
            return await awaitable
        finally:
            completed = time.perf_counter()
            timing["phases"][name] = {
                "started_at_seconds": started - self._run_started_perf,
                "completed_at_seconds": completed - self._run_started_perf,
                "duration_seconds": completed - started,
            }

    def _batchbundle_rounds_for(self, value_count):
        return batchbundle_batch_count(value_count, self.t)

    def _batchrand_rounds_for(self, value_count):
        return batchrand_batch_count(value_count, self.t)

    def _channel(self, prefix, destination_layer):
        tag = f"{prefix}_{destination_layer}"
        return self.get_send(tag), self.subscribe_recv(tag)

    def _input_channel(self, destination_layer, dealer_id):
        tag = f"A_SHUF_INPUT_{destination_layer}_{dealer_id}"
        return self.get_send(tag), self.subscribe_recv(tag)

    @staticmethod
    def _ack_tag(destination_layer):
        return f"ACK_SHUF_{destination_layer}"

    def _committee_ids(self, layer):
        return range(layer * self.n, (layer + 1) * self.n)

    async def _send_handoff_ack(self, source_layer, received_kinds):
        destination_layer = self.layer_ID
        ack_send = self.get_send(self._ack_tag(destination_layer))
        payload = {
            "marker": HANDOFF_ACK_MARKER,
            "run_id": self.run_id,
            "source_layer": source_layer,
            "destination_layer": destination_layer,
            "party_id": self.my_id,
            "received": tuple(sorted(received_kinds)),
        }
        for source_gid in self._committee_ids(source_layer):
            ack_send(source_gid, payload)

    async def _wait_handoff_ack(self, destination_layer, required_kinds):
        ack_recv = self.subscribe_recv(self._ack_tag(destination_layer))
        expected_senders = set(self._committee_ids(destination_layer))
        received_senders = set()
        deadline = time.monotonic() + self.ack_timeout
        required_kinds = tuple(sorted(required_kinds))

        while len(received_senders) < self.ack_threshold:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                sender, payload = await asyncio.wait_for(ack_recv(), remaining)
            except asyncio.TimeoutError:
                break
            if sender not in expected_senders or not isinstance(payload, dict):
                continue
            if (
                payload.get("marker") != HANDOFF_ACK_MARKER
                or payload.get("run_id") != self.run_id
                or payload.get("source_layer") != self.layer_ID
                or payload.get("destination_layer") != destination_layer
                or tuple(payload.get("received", ())) != required_kinds
            ):
                continue
            received_senders.add(sender)

        if len(received_senders) < self.ack_threshold:
            missing = sorted(expected_senders - received_senders)
            raise RuntimeError(
                f"shuffle handoff ACK timeout layer={self.layer_ID}->"
                f"{destination_layer} threshold={self.ack_threshold} "
                f"received={len(received_senders)} missing={missing}"
            )
        return tuple(sorted(received_senders))

    async def _shuffle_batch_mult(self, mult_values, mult_triples, rec_id):
        """Use Beaver triples without changing the baseline ``mult`` method."""
        if not isinstance(rec_id, int) or rec_id < 0:
            raise ValueError("rec_id must be a non-negative integer")
        if len(mult_values) != len(mult_triples):
            raise ValueError("multiplication input/triple count mismatch")
        if not mult_values:
            return []

        openings = []
        for index, (operands, triple) in enumerate(zip(mult_values, mult_triples)):
            if len(operands) != 2:
                raise ValueError(f"multiplication {index} must have two operands")
            if len(triple) != 3:
                raise ValueError(f"Beaver triple {index} must have three elements")
            left, right = operands
            a_share, b_share, _ = triple
            openings.extend((left - a_share, right - b_share))

        opened = await self.robust_rec_step(openings, rec_id)
        if len(opened) != 2 * len(mult_values):
            raise RuntimeError(
                f"reconstruction returned {len(opened)} values, expected "
                f"{2 * len(mult_values)}"
            )

        outputs = []
        for index, triple in enumerate(mult_triples):
            gamma = opened[2 * index]
            epsilon = opened[2 * index + 1]
            a_share, b_share, c_share = triple
            outputs.append(
                c_share
                + gamma * b_share
                + epsilon * a_share
                + gamma * epsilon
            )
        return outputs

    def _checked_public_square_root(self, opened_value):
        square_int = int(opened_value) % Subgroup.BLS12_381
        if square_int == 0:
            return None
        root_int = self._mod_sqrt(square_int)
        if root_int is None:
            raise RuntimeError("opened random square is not a quadratic residue")
        if root_int * root_int % Subgroup.BLS12_381 != square_int:
            raise RuntimeError("opened random square failed square-root verification")
        return self.ZR(root_int)

    async def _normalize_random_signs(
        self,
        random_shares,
        square_triples,
        square_mult_rec_id,
        square_open_rec_id,
        target_signs=FIG12_SWITCHES_PER_LAYER,
    ):
        """Implement Algorithm 3 over a Continuum-sized candidate batch."""
        if square_mult_rec_id == square_open_rec_id:
            raise ValueError("square multiplication and opening rec_ids must differ")
        expected_candidates = randbit_candidate_capacity(self.t, target_signs)
        if len(random_shares) != expected_candidates:
            raise ValueError(
                f"expected {expected_candidates} random candidates, "
                f"got {len(random_shares)}"
            )
        if len(square_triples) != expected_candidates:
            raise ValueError(
                f"expected {expected_candidates} square triples, "
                f"got {len(square_triples)}"
            )

        square_inputs = [(share, share) for share in random_shares]
        square_shares = await self._shuffle_batch_mult(
            square_inputs, square_triples, square_mult_rec_id
        )
        opened_squares = await self.robust_rec_step(square_shares, square_open_rec_id)
        if len(opened_squares) != expected_candidates:
            raise RuntimeError(
                f"opened {len(opened_squares)} squares, expected {expected_candidates}"
            )

        signs = []
        selected_indices = []
        discarded_zeroes = 0
        for index, opened_square in enumerate(opened_squares):
            root = self._checked_public_square_root(opened_square)
            if root is None:
                discarded_zeroes += 1
                continue
            signs.append(random_shares[index] / root)
            selected_indices.append(index)
            if len(signs) == target_signs:
                break

        if len(signs) != target_signs:
            raise RuntimeError(
                "not enough nonzero random signs generated: "
                f"needed={target_signs}, got={len(signs)}, "
                f"candidates={expected_candidates}"
            )

        self._last_randbit_stats = {
            "candidates": expected_candidates,
            "selected_indices": tuple(selected_indices),
            "discarded_zeroes": discarded_zeroes,
        }
        return signs

    async def _run_switch_layer(
        self,
        state,
        pairs,
        signs,
        switch_triples,
        rec_id,
        expected_width=FIG12_INPUTS,
    ):
        """Evaluate one perfect-matching layer and preserve wire placement."""
        state = list(state)
        if len(state) != expected_width:
            raise ValueError(
                f"shuffle state width must be {expected_width}, got {len(state)}"
            )
        pairs = validate_switch_layer(expected_width, pairs)
        if len(signs) != len(pairs):
            raise ValueError("selector count does not match switch-pair count")
        if len(switch_triples) != len(pairs):
            raise ValueError("switch triple count does not match switch-pair count")

        differences = [state[left] - state[right] for left, right in pairs]
        products = await self._shuffle_batch_mult(
            list(zip(signs, differences)), switch_triples, rec_id
        )

        inv_two = self.ZR(1) / self.ZR(2)
        outputs = list(state)
        for (left, right), product in zip(pairs, products):
            pair_sum = state[left] + state[right]
            outputs[left] = (pair_sum - product) * inv_two
            outputs[right] = (pair_sum + product) * inv_two
        return outputs

    async def _start_input_sharing(self, destination_layer):
        public_inputs = [self.ZR(value) for value in range(1, self.shuffle_k + 1)]
        dealer_values = prepare_dealer_inputs(
            public_inputs,
            self.my_id,
            self.n,
            k=self.shuffle_k,
            zero=self.ZR(0),
        )
        input_send, input_recv = self._input_channel(destination_layer, self.my_id)
        resource = self._register_resource(
            ACSS_Pre(
                self.admpc_control_instance.pks_all[destination_layer],
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.sc,
                self.my_id,
                input_send,
                input_recv,
                self.pc,
                self.ZR,
                self.G1,
                mpc_instance=self,
            )
        )
        await resource.avss(0, values=dealer_values)

    async def _receive_input_shares(self):
        batch_size = inputs_per_dealer(self.shuffle_k, self.n)
        tasks = []
        for dealer_id in range(self.n):
            input_send, input_recv = self._input_channel(self.layer_ID, dealer_id)
            resource = self._register_resource(
                ACSS_Foll(
                    self.public_keys,
                    self.private_key,
                    self.g,
                    self.h,
                    self.n,
                    self.t,
                    self.deg,
                    self.sc,
                    self.my_id,
                    input_send,
                    input_recv,
                    self.pc,
                    self.ZR,
                    self.G1,
                    mpc_instance=self,
                )
            )
            tasks.append(asyncio.create_task(resource.avss(0, dealer_id, batch_size)))
        results = await asyncio.gather(*tasks)
        dealer_to_shares = {
            dealer: shares["msg"] for dealer, _, shares, _ in results
        }
        return merge_dealer_input_shares(
            dealer_to_shares, self.n, self.shuffle_k
        )

    def _new_bundle_pre(self, destination_layer):
        send, recv = self._channel("GR_SHUF_MASK", destination_layer)
        return self._register_resource(
            Bundle_Pre(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                self.matrix,
                mpc_instance=self,
            )
        )

    def _new_rand_pre(self, destination_layer):
        send, recv = self._channel("GR_SHUF_SIGN", destination_layer)
        return self._register_resource(
            Rand_Pre(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                self.matrix,
                mpc_instance=self,
            )
        )

    def _new_aprep_pre(self, destination_layer):
        send, recv = self._channel("AP_SHUF", destination_layer)
        return self._register_resource(
            APREP_Pre(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                self.matrix,
                mpc_instance=self,
            )
        )

    async def _start_next_preprocessing(self, destination_layer):
        candidates = randbit_candidate_capacity(self.t, self.shuffle_k // 2)
        triple_count = candidates + self.shuffle_k // 2
        bundle_pre = self._new_bundle_pre(destination_layer)
        rand_pre = self._new_rand_pre(destination_layer)
        aprep_pre = self._new_aprep_pre(destination_layer)
        await asyncio.gather(
            bundle_pre.run_bundle(
                self.shuffle_k, self._batchbundle_rounds_for(self.shuffle_k)
            ),
            rand_pre.run_rand(
                candidates, self._batchrand_rounds_for(candidates)
            ),
            aprep_pre.run_aprep(triple_count),
        )

    async def _receive_bundle(self):
        send, recv = self._channel("GR_SHUF_MASK", self.layer_ID)
        resource = self._register_resource(
            Bundle_Foll(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                self.matrix,
                mpc_instance=self,
            )
        )
        return await resource.run_bundle(
            self.shuffle_k, self._batchbundle_rounds_for(self.shuffle_k)
        )

    async def _receive_random_candidates(self):
        candidates = randbit_candidate_capacity(self.t, self.shuffle_k // 2)
        send, recv = self._channel("GR_SHUF_SIGN", self.layer_ID)
        resource = self._register_resource(
            Rand_Foll(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                self.matrix,
                mpc_instance=self,
            )
        )
        return await resource.run_rand(
            candidates, self._batchrand_rounds_for(candidates)
        )

    async def _receive_triples(self):
        triple_count = shuffle_triple_count(self.t, self.shuffle_k // 2)
        send, recv = self._channel("AP_SHUF", self.layer_ID)
        resource = self._register_resource(
            APREP_Foll(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                self.matrix,
                mpc_instance=self,
            )
        )
        return await resource.run_aprep(triple_count)

    async def _receive_transferred_state(self):
        send, recv = self._channel("TR_SHUF_STATE", self.layer_ID)
        resource = self._register_resource(
            Trans_Foll(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                mpc_instance=self,
            )
        )
        return await resource.run_trans(self.shuffle_k)

    async def _start_state_transfer(self, destination_layer, state, bundle):
        rand_shares, hat_rand_shares, w_list = bundle
        trans_randomness = [rand_shares[0]] + list(rand_shares) + list(
            hat_rand_shares
        )
        send, recv = self._channel("TR_SHUF_STATE", destination_layer)
        resource = self._register_resource(
            Trans_Pre(
                self.public_keys,
                self.private_key,
                self.g,
                self.h,
                self.n,
                self.t,
                self.deg,
                self.my_id,
                send,
                recv,
                self.pc,
                self.curve_params,
                mpc_instance=self,
            )
        )
        await resource.run_trans(state, trans_randomness, list(w_list))

    async def _run_input_layer(self):
        destination_layer = 1
        timing = self._new_phase_timing()
        ack_task = asyncio.create_task(
            self._measure_phase(
                timing,
                "handoff_ack_wait",
                self._wait_handoff_ack(
                    destination_layer, ("APREP", "BUNDLE", "INPUT", "RAND")
                ),
            )
        )
        await asyncio.gather(
            self._measure_phase(
                timing,
                "input_sharing",
                self._start_input_sharing(destination_layer),
            ),
            self._measure_phase(
                timing,
                "next_preprocessing",
                self._start_next_preprocessing(destination_layer),
            ),
        )
        acknowledgements = await ack_task
        return {
            "role": "input",
            "layer": self.layer_ID,
            "acked_by": acknowledgements,
            "phase_timing": timing,
        }

    async def _run_compute_layer(self):
        source_layer = self.layer_ID - 1
        timing = self._new_phase_timing()
        if self.layer_ID == 1:
            state_awaitable = self._receive_input_shares()
            state_kind = "INPUT"
        else:
            state_awaitable = self._receive_transferred_state()
            state_kind = "STATE"

        state_task = asyncio.create_task(
            self._measure_phase(timing, "state_receive", state_awaitable)
        )
        bundle_task = asyncio.create_task(
            self._measure_phase(timing, "bundle_receive", self._receive_bundle())
        )
        rand_task = asyncio.create_task(
            self._measure_phase(
                timing, "rand_candidates_receive", self._receive_random_candidates()
            )
        )
        triples_task = asyncio.create_task(
            self._measure_phase(timing, "aprep_receive", self._receive_triples())
        )

        async def acknowledge_received_materials():
            await asyncio.gather(
                state_task, bundle_task, rand_task, triples_task
            )
            await self._send_handoff_ack(
                source_layer, (state_kind, "BUNDLE", "RAND", "APREP")
            )

        incoming_ack_task = asyncio.create_task(
            self._measure_phase(
                timing, "incoming_ack_send", acknowledge_received_materials()
            )
        )

        # RandBit normalization depends only on candidates and APREP.  Starting
        # it as soon as those two inputs arrive exposes the actual part of
        # RandGen that is not hidden behind state delivery.
        candidates, triples = await asyncio.gather(rand_task, triples_task)
        square_triples, switch_triples = split_shuffle_triples(
            triples, self.t, self.shuffle_k // 2
        )
        signs = await self._measure_phase(
            timing,
            "rand_sign_normalization",
            self._normalize_random_signs(
                candidates,
                square_triples,
                square_mult_rec_id=100,
                square_open_rec_id=101,
                target_signs=self.shuffle_k // 2,
            ),
        )
        state = await state_task
        signs_ready = timing["phases"]["rand_sign_normalization"][
            "completed_at_seconds"
        ]
        state_ready = timing["phases"]["state_receive"]["completed_at_seconds"]
        timing["randgen_exposed_seconds"] = max(0.0, signs_ready - state_ready)
        timing["randgen_definition"] = (
            "positive tail from state-ready until normalized signs are ready; "
            "candidate/APREP work completed before state-ready is pipeline-hidden"
        )

        schedule_index = self.layer_ID - 1
        output_state = await self._measure_phase(
            timing,
            "switch_execution",
            self._run_switch_layer(
                state,
                self.shuffle_schedule[schedule_index],
                signs,
                switch_triples,
                rec_id=102,
                expected_width=self.shuffle_k,
            ),
        )
        bundle = await bundle_task
        await incoming_ack_task

        destination_layer = self.layer_ID + 1
        if self.layer_ID < self.switch_layers:
            required_kinds = ("APREP", "BUNDLE", "RAND", "STATE")
            ack_task = asyncio.create_task(
                self._measure_phase(
                    timing,
                    "handoff_ack_wait",
                    self._wait_handoff_ack(destination_layer, required_kinds),
                )
            )
            await asyncio.gather(
                self._measure_phase(
                    timing,
                    "next_preprocessing",
                    self._start_next_preprocessing(destination_layer),
                ),
                self._measure_phase(
                    timing,
                    "state_transfer",
                    self._start_state_transfer(
                        destination_layer, output_state, bundle
                    ),
                ),
            )
        else:
            ack_task = asyncio.create_task(
                self._measure_phase(
                    timing,
                    "handoff_ack_wait",
                    self._wait_handoff_ack(destination_layer, ("STATE",)),
                )
            )
            await self._measure_phase(
                timing,
                "state_transfer",
                self._start_state_transfer(
                    destination_layer, output_state, bundle
                ),
            )
        acknowledgements = await ack_task
        return {
            "role": "compute",
            "layer": self.layer_ID,
            "schedule_index": schedule_index,
            "acked_by": acknowledgements,
            "discarded_zeroes": self._last_randbit_stats["discarded_zeroes"],
            "phase_timing": timing,
        }

    @staticmethod
    def _multiset_digest(values):
        canonical = ",".join(str(value) for value in sorted(int(v) for v in values))
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()

    async def _run_output_layer(self):
        timing = self._new_phase_timing()
        state = await self._measure_phase(
            timing, "state_receive", self._receive_transferred_state()
        )
        reconstructed = await self._measure_phase(
            timing, "output_reconstruction", self.robust_rec_step(state, 103)
        )
        if len(reconstructed) != self.shuffle_k:
            raise RuntimeError(
                f"output reconstruction returned {len(reconstructed)} values, "
                f"expected {self.shuffle_k}"
            )
        expected = [self.ZR(value) for value in range(1, self.shuffle_k + 1)]
        input_digest = self._multiset_digest(expected)
        output_digest = self._multiset_digest(reconstructed)
        valid = input_digest == output_digest
        if not valid:
            raise RuntimeError("shuffle output is not a permutation of its input")
        await self._measure_phase(
            timing,
            "incoming_ack_send",
            self._send_handoff_ack(self.layer_ID - 1, ("STATE",)),
        )
        result = {
            "schema": "admpc-shuffle-result-v1",
            "role": "output",
            "layer": self.layer_ID,
            "k": self.shuffle_k,
            "mode": self.shuffle_mode,
            "switch_layers": self.switch_layers,
            "n": self.n,
            "t": self.t,
            "output_count": len(reconstructed),
            "input_multiset_digest": input_digest,
            "output_multiset_digest": output_digest,
            "permutation_valid": valid,
            "phase_timing": timing,
        }
        print("ADMPC_SHUFFLE_RESULT " + json.dumps(result, sort_keys=True))
        return result

    async def run_admpc(self, start_time):
        del start_time
        self._run_started_perf = time.perf_counter()
        if self.layer_ID == 0:
            result = await self._run_input_layer()
        elif self.layer_ID == self.physical_layers - 1:
            result = await self._run_output_layer()
        else:
            result = await self._run_compute_layer()
        self._last_result = result
        return result
