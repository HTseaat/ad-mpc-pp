import asyncio
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from adkg.acss import ACSS, adtrans_alg4_per_item_enabled
from adkg.broadcast.avid import AVID_DYNAMIC, AVIDMessageType
from adkg.elliptic_curve import Subgroup
from adkg.field import GF
from adkg.polynomial import EvalPoint, polynomials_over
from adkg.poly_commit_hybrid import PolyCommitHybrid
from adkg.robust_reconstruction import (
    find_inconsistent_dealers,
    robust_reconstruct_admpc,
)
from adkg.symmetric_crypto import SymmetricCrypto
from adkg.trans import Trans_Foll
from pypairing import G1, ZR, blsmultiexp as multiexp


class DynamicAvidTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_destination_recovers_only_its_indexed_payload(self):
        committee_size = 4
        threshold = 1
        dealer_local_id = 2
        member_list = [7, 20, 31, 42, 53]
        queues = {global_id: asyncio.Queue() for global_id in member_list}

        def send_for(sender):
            def send(destination, message):
                queues[destination].put_nowait((sender, message))

            return send

        async def recv_for(global_id):
            return await queues[global_id].get()

        sid = "adtrans-avid-test"
        payloads = [
            b"receiver-0",
            b"receiver-1-with-a-longer-payload",
            b"receiver-2",
            b"receiver-3" * 11,
        ]

        recipient_avids = []
        recipient_tasks = []
        for index, global_id in enumerate(member_list[1:]):
            avid = AVID_DYNAMIC(
                committee_size + 1,
                threshold,
                dealer_local_id,
                lambda global_id=global_id: recv_for(global_id),
                send_for(global_id),
                committee_size,
                member_list,
            )
            recipient_avids.append(avid)
            recipient_tasks.append(
                asyncio.create_task(avid.disperse(sid, index))
            )

        dealer = AVID_DYNAMIC(
            committee_size + 1,
            threshold,
            dealer_local_id,
            lambda: recv_for(member_list[0]),
            send_for(member_list[0]),
            committee_size,
            member_list,
        )
        await dealer.disperse(sid, dealer_local_id, payloads)

        recovered = await asyncio.wait_for(
            asyncio.gather(
                *(
                    avid.retrieve(sid, index)
                    for index, avid in enumerate(recipient_avids)
                )
            ),
            timeout=5,
        )
        self.assertEqual(recovered, payloads)

        for task in recipient_tasks:
            task.cancel()
        await asyncio.gather(*recipient_tasks, return_exceptions=True)

    async def test_echo_and_ready_do_not_add_a_root_digest(self):
        sent = []
        member_list = [7, 20, 31, 42, 53]
        recv_queue = asyncio.Queue()

        avid = AVID_DYNAMIC(
            5,
            1,
            0,
            recv_queue.get,
            lambda destination, message: sent.append((destination, message)),
            4,
            member_list,
        )
        avid.broadcast(("sid", AVIDMessageType.ECHO))
        avid.broadcast(("sid", AVIDMessageType.READY))

        self.assertEqual(len(sent), 8)
        self.assertTrue(all(len(message) == 2 for _, message in sent))


class AdtransSplitSerializationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.n = 4
        self.t = 1
        self.g = G1.rand(b"g")
        self.h = G1.rand(b"h")
        self.private_keys = [ZR.random() for _ in range(self.n)]
        self.public_keys = [self.g ** key for key in self.private_keys]
        self.recv_queue = asyncio.Queue()
        self.acss = ACSS(
            self.public_keys,
            None,
            self.g,
            self.h,
            self.n,
            self.t,
            self.t,
            2,
            0,
            lambda _destination, _message: None,
            self.recv_queue.get,
            PolyCommitHybrid(self.g, self.h, ZR, multiexp),
            ZR,
            G1,
        )
        self.acss.adtrans_alg4_per_item = False

    async def asyncTearDown(self):
        self.acss.kill()
        await asyncio.gather(
            self.acss.subscribe_recv_task, return_exceptions=True
        )

    async def test_dealer_returns_public_rbc_and_n_private_ciphertexts(self):
        batch_size = 3
        values = [ZR.random() for _ in range(batch_size)]
        randomness = [ZR.random() for _ in range(1 + 2 * batch_size)]
        w_list = [G1.rand(bytes([index + 1])) for index in range(batch_size)]

        public_msg, ciphertexts = self.acss._get_dealer_msg_trans_log(
            (values, randomness, w_list), self.n
        )

        self.assertIsInstance(public_msg, bytes)
        self.assertEqual(len(ciphertexts), self.n)
        self.assertTrue(all(isinstance(item, bytes) for item in ciphertexts))
        self.assertTrue(all(item not in public_msg for item in ciphertexts))

        public_fields = self.acss.decode_public_trans_log(
            public_msg, batch_size
        )
        ephkey = public_fields[-1]
        for index, ciphertext in enumerate(ciphertexts):
            shared_key = ephkey ** self.private_keys[index]
            plaintext = SymmetricCrypto.decrypt(
                shared_key.__getstate__(), ciphertext
            )
            self.assertGreater(len(plaintext), batch_size * self.acss.sr.f_size)

        with self.assertRaises(ValueError):
            self.acss.decode_public_trans_log(
                public_msg + ciphertexts[0], batch_size
            )

    async def test_per_item_mode_changes_only_public_consistency_fields(self):
        batch_size = 3

        def inputs():
            return (
                [ZR.random() for _ in range(batch_size)],
                [ZR.random() for _ in range(1 + 2 * batch_size)],
                [G1.rand(bytes([index + 11])) for index in range(batch_size)],
            )

        self.acss.adtrans_alg4_per_item = False
        aggregate_public, aggregate_ciphertexts = (
            self.acss._get_dealer_msg_trans_log(inputs(), self.n)
        )

        self.acss.adtrans_alg4_per_item = True
        per_item_public, per_item_ciphertexts = (
            self.acss._get_dealer_msg_trans_log(inputs(), self.n)
        )
        public_fields = self.acss.decode_public_trans_log(
            per_item_public, batch_size
        )

        omega, mask, hat_mask, w = public_fields[2:6]
        self.assertEqual(len(omega), batch_size)
        self.assertEqual(len(mask), batch_size)
        self.assertEqual(len(hat_mask), batch_size)
        self.assertEqual(len(w), batch_size)
        self.assertEqual(
            len(per_item_public) - len(aggregate_public),
            (batch_size - 1) * (
                2 * self.acss.sr.g_size + 2 * self.acss.sr.f_size
            ),
        )
        self.assertEqual(
            [len(item) for item in per_item_ciphertexts],
            [len(item) for item in aggregate_ciphertexts],
        )

        # A mixed deployment must reject rather than reinterpret the other
        # public schema.
        self.acss.adtrans_alg4_per_item = False
        with self.assertRaises(ValueError):
            self.acss.decode_public_trans_log(per_item_public, batch_size)
        self.acss.adtrans_alg4_per_item = True
        with self.assertRaises(ValueError):
            self.acss.decode_public_trans_log(aggregate_public, batch_size)


class _ControlledFollowerACSS:
    def __init__(self, dealer_results):
        self.dealer_results = dealer_results
        self.metrics_protocol = None
        self.killed = False

    async def avss_trans(self, _avss_id, dealer_id, _len_values):
        return await self.dealer_results[dealer_id]

    def kill(self):
        self.killed = True


class AdtransQuorumCollectorTests(unittest.IsolatedAsyncioTestCase):
    def _make_follower(self):
        follower = Trans_Foll.__new__(Trans_Foll)
        follower.n = 4
        follower.t = 1
        follower.my_id = 0
        follower.public_keys = None
        follower.private_key = None
        follower.g = None
        follower.h = None
        follower.deg = 1
        follower.sc = 2
        follower.pc = None
        follower.ZR = ZR
        follower.G1 = G1
        follower.get_send = lambda _tag: None
        follower.subscribe_recv = lambda _tag: None
        follower.mpc_instance = SimpleNamespace(layer_ID=1)
        return follower

    @staticmethod
    def _result(dealer):
        return (
            dealer,
            0,
            f"shares-{dealer}",
            f"commits-{dealer}",
            f"omega-{dealer}",
            f"mask-{dealer}",
            f"hat-mask-{dealer}",
            f"w-{dealer}",
        )

    async def test_quorum_advances_and_late_dealer_is_collected(self):
        follower = self._make_follower()
        recorded_quorums = []
        follower.mpc_instance.metrics_recorder = SimpleNamespace(
            record_proof_quorum=lambda **entry: recorded_quorums.append(entry)
        )
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]
        instances = []

        def make_acss(*_args, **_kwargs):
            instance = _ControlledFollowerACSS(dealer_results)
            instances.append(instance)
            return instance

        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = loop.create_future()

        with patch("adkg.trans.ACSS_Foll", side_effect=make_acss):
            collector = asyncio.create_task(
                follower.acss_step(
                    1, outputs, quorum_proposal, dealer_ready
                )
            )
            await asyncio.sleep(0)

            # The quorum is based on completion/validity, not dealer IDs.
            for dealer in (3, 0, 2):
                dealer_results[dealer].set_result(self._result(dealer))
                await asyncio.sleep(0)

            proposal = await asyncio.wait_for(
                quorum_proposal, timeout=0.2
            )
            self.assertEqual(proposal, (0, 2, 3))
            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertTrue(all(dealer_ready[d].is_set() for d in proposal))
            self.assertFalse(dealer_ready[1].is_set())
            self.assertFalse(collector.done())
            self.assertEqual(recorded_quorums, [{
                "protocol": "adtrans",
                "target_layer": 1,
                "receiver_local_id": 0,
                "dealer_ids": (0, 2, 3),
                "required_count": 3,
            }])

            dealer_results[1].set_result(self._result(1))
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertEqual(set(outputs), {0, 1, 2, 3})
            self.assertTrue(dealer_ready[1].is_set())
            self.assertEqual(len(follower.acss_instances), follower.n)

        for instance in instances:
            instance.kill()

    async def test_failed_dealer_does_not_fail_valid_quorum(self):
        follower = self._make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]

        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = loop.create_future()

        with patch(
            "adkg.trans.ACSS_Foll",
            side_effect=lambda *_args, **_kwargs: _ControlledFollowerACSS(
                dealer_results
            ),
        ):
            collector = asyncio.create_task(
                follower.acss_step(
                    1, outputs, quorum_proposal, dealer_ready
                )
            )
            await asyncio.sleep(0)

            dealer_results[1].set_exception(ValueError("invalid dealer"))
            for dealer in (0, 2, 3):
                dealer_results[dealer].set_result(self._result(dealer))

            proposal = await asyncio.wait_for(
                quorum_proposal, timeout=0.2
            )
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertEqual(proposal, (0, 2, 3))
            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertFalse(dealer_ready[1].is_set())


class AdtransAttackCandidateSelectionTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _follower():
        follower = Trans_Foll.__new__(Trans_Foll)
        follower.n = 4
        return follower

    @staticmethod
    def _fault_controller(observes_attack):
        return SimpleNamespace(
            observes_attack_destination=lambda: observes_attack
        )

    async def test_normal_path_keeps_initial_quorum_without_waiting_for_collector(self):
        follower = self._follower()
        follower.acss_task = asyncio.get_running_loop().create_future()

        candidates = await asyncio.wait_for(
            follower._select_reconstruction_dealers(
                [0, 2, 3],
                {0: object(), 2: object(), 3: object()},
                self._fault_controller(False),
            ),
            timeout=0.2,
        )

        self.assertEqual(candidates, [0, 2, 3])
        self.assertFalse(follower.acss_task.done())
        follower.acss_task.cancel()

    async def test_figure10_attack_waits_for_all_responsive_candidates(self):
        follower = self._follower()
        acss_outputs = {0: object(), 2: object(), 3: object()}
        release_late_dealer = asyncio.Event()

        async def finish_collection():
            await release_late_dealer.wait()
            acss_outputs[1] = object()

        follower.acss_task = asyncio.create_task(finish_collection())
        selection = asyncio.create_task(
            follower._select_reconstruction_dealers(
                [0, 2, 3],
                acss_outputs,
                self._fault_controller(True),
            )
        )
        await asyncio.sleep(0)
        self.assertFalse(selection.done())

        release_late_dealer.set()
        candidates = await asyncio.wait_for(selection, timeout=0.2)
        self.assertEqual(candidates, [0, 1, 2, 3])

    async def test_figure10_attack_fails_if_a_candidate_is_rejected(self):
        follower = self._follower()

        async def finish_collection():
            return None

        follower.acss_task = asyncio.create_task(finish_collection())
        with self.assertRaisesRegex(
            RuntimeError, "requires all n responsive, fully verified candidates"
        ):
            await follower._select_reconstruction_dealers(
                [0, 2, 3],
                {0: object(), 2: object(), 3: object()},
                self._fault_controller(True),
            )

    async def test_n16_full_set_recovers_and_filters_forked_suffix(self):
        n, t = 16, 5
        field = GF(Subgroup.BLS12_381)
        point = EvalPoint(field, n, use_omega_powers=False)
        expected_poly = polynomials_over(field)([3, 5, 7, 11, 13, 17])
        shares = [expected_poly(point(dealer)) for dealer in range(n)]
        for dealer in range(n - t, n):
            shares[dealer] += field(1)

        frozen = [0, 1, 2, 3, 4, 5, 6, 8, 9, 13, 15]
        partial_poly, partial_errors = await robust_reconstruct_admpc(
            shares, frozen, field, t, point, t
        )
        self.assertIsNone(partial_poly)
        self.assertIsNone(partial_errors)

        recovered_poly, decoder_errors = await robust_reconstruct_admpc(
            shares, list(range(n)), field, t, point, t
        )
        self.assertEqual(recovered_poly, expected_poly)
        self.assertEqual(decoder_errors, set())
        self.assertEqual(
            find_inconsistent_dealers(
                recovered_poly, shares, list(range(n)), point
            ),
            [11, 12, 13, 14, 15],
        )


class AdtransVerificationSchedulingTests(unittest.TestCase):
    def test_algorithm4_switch_is_strict_and_defaults_to_aggregate(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ADTRANS_ALG4_PER_ITEM", None)
            self.assertFalse(adtrans_alg4_per_item_enabled(None))
        self.assertFalse(adtrans_alg4_per_item_enabled("off"))
        self.assertTrue(adtrans_alg4_per_item_enabled("1"))
        with self.assertRaises(ValueError):
            adtrans_alg4_per_item_enabled("sometimes")

    def test_high_numbered_dealer_runs_existing_crypto_checks(self):
        acss = ACSS.__new__(ACSS)
        acss.private_key = ZR.random()
        acss.sr = SimpleNamespace(
            f_size=1,
            deserialize_fs=lambda _payload: [ZR.random()],
        )
        acss.deserialize_witness = lambda _payload, _count: ["witness"]
        acss.mpc_instance = SimpleNamespace(
            fault_controller=None,
            metrics_recorder=None,
        )
        acss.metrics_protocol = "adtrans"
        acss.adtrans_alg4_per_item = False
        acss.my_id = 0
        acss.t = 1
        verification_calls = []
        consistency_calls = []
        acss.poly_commit_log = SimpleNamespace(
            batch_verify_eval_rs=lambda *args: (
                verification_calls.append(args) or True
            )
        )
        acss.verify_consis_bundle = lambda *args: (
            consistency_calls.append(args) or True
        )
        acss.acss_status = {}
        acss.data = {}

        ephkey = G1.rand(b"ephkey")
        with patch.object(
            SymmetricCrypto, "decrypt", return_value=b"pw"
        ):
            accepted = acss.verify_proposal_trans_log(
                dealer_id=3,
                dispersal_msg=b"ciphertext",
                commit_peds=[G1.rand(b"ped")],
                commit_tests=[G1.rand(b"test")],
                omega=[G1.rand(b"omega")],
                mask=[ZR.random()],
                hat_mask=[ZR.random()],
                w=[G1.rand(b"w")],
                shared=[G1.rand(b"shared")],
                ephkey=ephkey,
                poly_num=1,
            )

        self.assertTrue(accepted)
        self.assertEqual(len(verification_calls), 1)
        self.assertEqual(len(consistency_calls), 1)
        self.assertTrue(acss.acss_status[3])

    def test_per_item_mode_verifies_every_tuple_then_stores_aggregate_view(self):
        batch_size = 3
        acss = ACSS.__new__(ACSS)
        acss.private_key = ZR.random()
        acss.sr = SimpleNamespace(
            f_size=1,
            deserialize_fs=lambda payload: [
                ZR.random() for _ in range(len(payload))
            ],
        )
        acss.deserialize_witness = lambda _payload, _count: ["witness"]
        acss.mpc_instance = SimpleNamespace(
            fault_controller=None,
            metrics_recorder=None,
        )
        acss.metrics_protocol = "adtrans"
        acss.adtrans_alg4_per_item = True
        acss.my_id = 0
        acss.t = 1
        verification_calls = []
        consistency_calls = []
        acss.poly_commit_log = SimpleNamespace(
            batch_verify_eval_rs=lambda *args: (
                verification_calls.append(args) or True
            )
        )
        acss.verify_consis_bundle = lambda *args: (
            consistency_calls.append(args) or True
        )
        acss.acss_status = {}
        acss.data = {}

        commit_peds = [
            G1.rand(bytes([31 + index])) for index in range(batch_size)
        ]
        commit_tests = [
            G1.rand(bytes([41 + index])) for index in range(batch_size)
        ]
        omega = [G1.rand(bytes([51 + index])) for index in range(batch_size)]
        mask = [ZR.random() for _ in range(batch_size)]
        hat_mask = [ZR.random() for _ in range(batch_size)]
        w = [G1.rand(bytes([61 + index])) for index in range(batch_size)]

        with patch.object(SymmetricCrypto, "decrypt", return_value=b"pppw"):
            accepted = acss.verify_proposal_trans_log(
                dealer_id=3,
                dispersal_msg=b"ciphertext",
                commit_peds=commit_peds,
                commit_tests=commit_tests,
                omega=omega,
                mask=mask,
                hat_mask=hat_mask,
                w=w,
                shared=[G1.rand(b"shared")],
                ephkey=G1.rand(b"ephkey"),
                poly_num=batch_size,
            )

        self.assertTrue(accepted)
        self.assertEqual(len(verification_calls), 1)
        self.assertEqual(len(consistency_calls), batch_size)
        for index, call in enumerate(consistency_calls):
            self.assertEqual(call, (
                commit_peds[index], mask[index], hat_mask[index], omega[index]
            ))
        stored = acss.data[3]
        self.assertFalse(isinstance(stored[4], list))
        self.assertFalse(isinstance(stored[5], list))
        self.assertFalse(isinstance(stored[6], list))
        self.assertFalse(isinstance(stored[7], list))


if __name__ == "__main__":
    unittest.main()
