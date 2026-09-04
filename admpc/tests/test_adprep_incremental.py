import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pypairing import G1, ZR, dotprod

from adkg.aprep import APREP_Foll
from adkg.polynomial import polynomials_over
from adkg.utils.bitmap import Bitmap


class _ControlledFollowerACSS:
    def __init__(self, dealer_results):
        self.dealer_results = dealer_results
        self.killed = False

    async def avss_aprep(self, _avss_id, dealer_id, _cm):
        return await self.dealer_results[dealer_id]

    def kill(self):
        self.killed = True


class _FakeRobustRec:
    def kill(self):
        pass


def _make_follower():
    follower = APREP_Foll.__new__(APREP_Foll)
    follower.n = 4
    follower.t = 1
    follower.deg = 1
    follower.sc = 2
    follower.my_id = 0
    follower.public_keys = [None] * follower.n
    follower.private_key = None
    follower.g = None
    follower.h = None
    follower.pc = None
    follower.ZR = ZR
    follower.G1 = G1
    follower.dotprod = dotprod
    follower.poly = polynomials_over(ZR)
    follower.get_send = lambda _tag: None
    follower.subscribe_recv = lambda _tag: None
    follower.subscribe_recv_task = asyncio.create_task(
        asyncio.Event().wait()
    )
    follower.mpc_instance = SimpleNamespace(layer_ID=1)
    follower.matrix = None
    follower.quorum_size = follower.n - follower.t
    follower.aprep_session = 1
    follower.member_list = list(range(4, 8))
    follower.acss_instances = []
    follower.acss_tasks = []
    follower.validation_tasks = []
    follower.rbc_tasks = []
    follower.agreement_work_tasks = []
    follower.rec = _FakeRobustRec()
    return follower


def _dealer_output(dealer, *, valid=True, cm=1):
    flat = []
    for index in range(cm):
        a = ZR(dealer + index + 2)
        b = ZR(2 * dealer + index + 3)
        c = a * b
        if not valid and index == 0:
            c += ZR(1)
        flat.extend((a, b, c))
    for index in range(cm):
        a = ZR(3 * dealer + index + 5)
        b = ZR(4 * dealer + index + 7)
        flat.extend((a, b, a * b))
    return {
        "shares": {"msg": [flat]},
        "commits": f"commitments-{dealer}",
    }


def _bacss_result(dealer, *, valid=True, cm=1):
    output = _dealer_output(dealer, valid=valid, cm=cm)
    return dealer, 0, output["shares"], output["commits"]


async def _identity_open(shares, _phase, _dealer=None):
    # The unit fixtures use degree-zero sharings, so their local value is also
    # the reconstructed public value.
    return list(shares)


class ADprepIncrementalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await asyncio.sleep(0)

    async def test_bacss_collector_tracks_real_dealer_and_isolates_failure(self):
        follower = _make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]
        instances = []

        def make_acss(*_args, **_kwargs):
            instance = _ControlledFollowerACSS(dealer_results)
            instances.append(instance)
            return instance

        outputs = {}
        states = [follower.PENDING_BACSS] * follower.n
        bacss_decided = [asyncio.Event() for _ in range(follower.n)]
        dealer_decided = [asyncio.Event() for _ in range(follower.n)]

        with patch("adkg.aprep.ACSS_Foll", side_effect=make_acss):
            collector = asyncio.create_task(follower.acss_step(
                1, outputs, states, bacss_decided, dealer_decided
            ))
            await asyncio.sleep(0)
            for dealer in (3, 0, 2):
                dealer_results[dealer].set_result(_bacss_result(dealer))
            for _ in range(20):
                if set(outputs) == {0, 2, 3}:
                    break
                await asyncio.sleep(0)

            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertFalse(collector.done())
            self.assertEqual(states[2], follower.BACSS_READY)
            self.assertTrue(bacss_decided[2].is_set())
            self.assertFalse(dealer_decided[2].is_set())

            dealer_results[1].set_exception(ValueError("invalid BACSS"))
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertEqual(states[1], follower.INVALID)
            self.assertTrue(bacss_decided[1].is_set())
            self.assertTrue(dealer_decided[1].is_set())

        follower.kill()
        self.assertTrue(all(instance.killed for instance in instances))
        await asyncio.gather(
            follower.subscribe_recv_task, return_exceptions=True
        )

    async def test_challenge_is_not_opened_before_its_bacss_is_ready(self):
        follower = _make_follower()
        calls = []

        async def record_open(shares, phase, dealer=None):
            calls.append((phase, dealer, list(shares)))
            return list(shares)

        follower.robust_rec_step = record_open
        states = [follower.PENDING_BACSS] * follower.n
        bacss_decided = [asyncio.Event() for _ in range(follower.n)]
        dealer_decided = [asyncio.Event() for _ in range(follower.n)]
        quorum = asyncio.get_running_loop().create_future()
        outputs = {}
        triples = {}
        rec_tau = {}
        valid_dealers = set()

        validator = asyncio.create_task(follower._validate_dealer(
            2, 1, [ZR(11)] * follower.n, outputs, states,
            bacss_decided, dealer_decided, triples, rec_tau,
            valid_dealers, quorum,
        ))
        await asyncio.sleep(0)
        self.assertEqual(calls, [])

        outputs[2] = _dealer_output(2)
        states[2] = follower.BACSS_READY
        bacss_decided[2].set()
        await asyncio.wait_for(validator, timeout=0.2)

        self.assertEqual(
            [(phase, dealer) for phase, dealer, _ in calls],
            [("random", 2), ("rho-sigma", 2), ("tau", 2)],
        )
        self.assertEqual(states[2], follower.VALID)
        self.assertTrue(dealer_decided[2].is_set())
        self.assertFalse(quorum.done())

        follower.kill()
        await asyncio.gather(
            follower.subscribe_recv_task, return_exceptions=True
        )

    async def test_nonzero_tau_is_excluded_and_other_dealers_form_quorum(self):
        follower = _make_follower()
        follower.robust_rec_step = _identity_open
        states = [follower.BACSS_READY] * follower.n
        bacss_decided = [asyncio.Event() for _ in range(follower.n)]
        dealer_decided = [asyncio.Event() for _ in range(follower.n)]
        for event in bacss_decided:
            event.set()
        outputs = {
            dealer: _dealer_output(dealer, valid=(dealer != 1))
            for dealer in range(follower.n)
        }
        triples = {}
        rec_tau = {}
        valid_dealers = set()
        quorum = asyncio.get_running_loop().create_future()
        challenges = [ZR(11 + dealer) for dealer in range(follower.n)]

        await asyncio.gather(*[
            follower._validate_dealer(
                dealer, 1, challenges, outputs, states,
                bacss_decided, dealer_decided, triples, rec_tau,
                valid_dealers, quorum,
            )
            for dealer in range(follower.n)
        ])

        self.assertEqual(states[1], follower.INVALID)
        self.assertNotEqual(rec_tau[1][0], ZR(0))
        self.assertEqual(valid_dealers, {0, 2, 3})
        self.assertEqual(set(triples), {0, 2, 3})
        self.assertEqual(await quorum, (0, 2, 3))
        self.assertTrue(all(event.is_set() for event in dealer_decided))

        follower.kill()
        await asyncio.gather(
            follower.subscribe_recv_task, return_exceptions=True
        )

    async def test_exact_proposal_waits_for_tau_decisions(self):
        follower = _make_follower()
        states = [follower.PENDING_BACSS] * follower.n
        dealer_decided = [asyncio.Event() for _ in range(follower.n)]
        encoded = follower._encode_proposal((1, 2, 3))

        predicate = asyncio.create_task(follower._proposal_is_valid(
            encoded, states, dealer_decided
        ))
        await asyncio.sleep(0)
        self.assertFalse(predicate.done())

        for dealer in (1, 2, 3):
            states[dealer] = follower.VALID
            dealer_decided[dealer].set()
        self.assertTrue(await asyncio.wait_for(predicate, timeout=0.2))

        states[2] = follower.INVALID
        self.assertFalse(await follower._proposal_is_valid(
            encoded, states, dealer_decided
        ))

        too_small = Bitmap(follower.n)
        too_small.set_bit(1)
        too_small.set_bit(2)
        self.assertFalse(await follower._proposal_is_valid(
            bytes(too_small.array), states, dealer_decided
        ))

        noncanonical = bytearray(encoded)
        noncanonical[0] |= 1
        self.assertIsNone(follower._decode_proposal(noncanonical))

        follower.kill()
        await asyncio.gather(
            follower.subscribe_recv_task, return_exceptions=True
        )

    async def test_sparse_common_set_is_relabelled_by_matrix_position(self):
        follower = _make_follower()
        follower.robust_rec_step = _identity_open
        triples = {
            0: [[ZR(2), ZR(3), ZR(6)]],
            1: [[ZR(999), ZR(999), ZR(1)]],
            2: [[ZR(5), ZR(7), ZR(35)]],
            3: [[ZR(11), ZR(13), ZR(143)]],
        }
        rbc_values = [None, [0, 2, 3], [0, 1, 2], None]
        rbc_signal = asyncio.Event()
        rbc_signal.set()

        result = await follower.new_triples(
            triples, 1, rbc_values, rbc_signal
        )

        self.assertEqual(follower.common_subset, (0, 2, 3))
        self.assertEqual(result, [[ZR(14), ZR(19), ZR(266)]])
        self.assertEqual(result[0][2], result[0][0] * result[0][1])

        follower.kill()
        await asyncio.gather(
            follower.subscribe_recv_task, return_exceptions=True
        )

    async def test_run_uses_n_challenges_and_does_not_wait_for_all_bacss(self):
        follower = _make_follower()
        requested = []
        agreed = []

        async def fake_rand(count):
            requested.append(count)
            return [ZR(11 + dealer) for dealer in range(count)]

        async def fake_acss(
                cm, outputs, states, bacss_decided, _dealer_decided):
            for dealer in (0, 2, 3):
                outputs[dealer] = _dealer_output(dealer, cm=cm)
                states[dealer] = follower.BACSS_READY
                bacss_decided[dealer].set()
            await asyncio.Event().wait()

        async def fake_agreement(
                proposal, _triples, _states, _dealer_decided, _cm):
            agreed.append(tuple(proposal))

            async def finish_common_subset():
                return None

            async def extract():
                return [[ZR(7), ZR(8), ZR(56)]]

            return finish_common_subset(), extract(), []

        follower.gen_rand_step = fake_rand
        follower.acss_step = fake_acss
        follower.agreement = fake_agreement
        follower.robust_rec_step = _identity_open

        result = await asyncio.wait_for(follower.run_aprep(1), timeout=0.2)
        self.assertEqual(result, [[ZR(7), ZR(8), ZR(56)]])
        self.assertEqual(requested, [follower.n])
        self.assertEqual(agreed, [(0, 2, 3)])
        self.assertFalse(follower.acss_task.done())
        self.assertEqual(follower.dealer_states[1], follower.PENDING_BACSS)

        cleanup = [
            follower.acss_task,
            follower.validation_watcher,
            follower.subscribe_recv_task,
            *follower.validation_tasks,
        ]
        follower.kill()
        await asyncio.gather(*cleanup, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
