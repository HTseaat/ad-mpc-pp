import asyncio
import unittest
from unittest.mock import patch

from pypairing import G1, ZR, blsmultiexp as multiexp, dotprod

from adkg.robust_rec import Robust_Rec
from adkg.utils.serilization import Serial


def _make_rec(n, t, my_id=0):
    rec = Robust_Rec.__new__(Robust_Rec)
    rec.n = n
    rec.t = t
    rec.deg = t
    rec.my_id = my_id
    rec.ZR = ZR
    rec.G1 = G1
    rec.global_num = 0
    rec.tasks = []
    rec.get_send = lambda _tag: None
    rec.subscribe_recv = lambda _tag: None
    rec.subscribe_recv_task = asyncio.create_task(asyncio.Event().wait())
    return rec


def _dealer_vector(dealer, polynomials):
    x = dealer + 1
    return [
        ZR(sum(coefficient * (x ** degree)
               for degree, coefficient in enumerate(coefficients)))
        for coefficients in polynomials
    ]


class IncrementalRobustRecTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        # Let cancellation callbacks consume task exceptions before asyncio's
        # debug-mode loop checks for leaked tasks.
        await asyncio.sleep(0)

    async def test_consistent_high_id_quorum_does_not_wait_for_all_n(self):
        rec = _make_rec(n=4, t=1)
        serializer = Serial(G1)
        outputs = [asyncio.Queue() for _ in range(rec.n)]
        polynomials = [(17, 3), (29, 5)]

        # Dealer 0 never responds.  The sparse/high-ID honest quorum is enough.
        for dealer in (1, 2, 3):
            outputs[dealer].put_nowait(bytes(serializer.serialize_fs(
                _dealer_vector(dealer, polynomials)
            )))

        values, errors, received = await asyncio.wait_for(
            rec._incremental_batch_decode(
                outputs, serializer, len(polynomials)
            ),
            timeout=0.2,
        )
        self.assertEqual([int(value) for value in values], [17, 29])
        self.assertEqual(errors, set())
        self.assertEqual(received, (1, 2, 3))

        rec.kill()

    async def test_one_error_and_one_omission_finishes_when_bound_is_two(self):
        rec = _make_rec(n=7, t=2)
        serializer = Serial(G1)
        outputs = [asyncio.Queue() for _ in range(rec.n)]
        polynomials = [(41, 2, 7), (73, 11, 3)]

        bad = _dealer_vector(0, polynomials)
        bad[0] += ZR(12345)
        outputs[0].put_nowait(bytes(serializer.serialize_fs(bad)))
        # Dealer 1 is the second faulty party and remains silent.  Five honest
        # vectors plus the one erroneous vector suffice to locate that error.
        for dealer in (2, 3, 4, 5, 6):
            outputs[dealer].put_nowait(bytes(serializer.serialize_fs(
                _dealer_vector(dealer, polynomials)
            )))

        values, errors, received = await asyncio.wait_for(
            rec._incremental_batch_decode(
                outputs, serializer, len(polynomials)
            ),
            timeout=0.2,
        )
        self.assertEqual([int(value) for value in values], [41, 73])
        self.assertEqual(errors, {0})
        self.assertEqual(set(received), {0, 2, 3, 4, 5, 6})

        rec.kill()

    async def test_malformed_output_is_rejected_without_poisoning_quorum(self):
        rec = _make_rec(n=4, t=1)
        serializer = Serial(G1)
        outputs = [asyncio.Queue() for _ in range(rec.n)]
        polynomials = [(101, 9)]

        outputs[0].put_nowait(b"not-a-field-vector")
        for dealer in (1, 2, 3):
            outputs[dealer].put_nowait(bytes(serializer.serialize_fs(
                _dealer_vector(dealer, polynomials)
            )))

        values, errors, received = await asyncio.wait_for(
            rec._incremental_batch_decode(outputs, serializer, 1),
            timeout=0.2,
        )
        self.assertEqual([int(value) for value in values], [101])
        self.assertEqual(errors, set())
        self.assertEqual(received, (1, 2, 3))

        rec.kill()

    async def test_batch_run_keeps_late_rbc_responder_off_critical_path(self):
        rec = _make_rec(n=4, t=1, my_id=1)
        serializer = Serial(G1)
        polynomials = [(13, 4), (23, 8)]
        payloads = [
            bytes(serializer.serialize_fs(_dealer_vector(dealer, polynomials)))
            for dealer in range(rec.n)
        ]
        release = [asyncio.Event() for _ in range(rec.n)]
        for dealer in (1, 2, 3):
            release[dealer].set()

        async def fake_rbc(
            _sid, _pid, _n, _f, leader, predicate, rbc_input, output,
            _send, _receive, _member_list,
        ):
            await release[leader].wait()
            payload = rbc_input if leader == rec.my_id else payloads[leader]
            if await predicate(payload):
                output(payload)

        with patch("adkg.robust_rec.optqrbc_dynamic", new=fake_rbc):
            values = await asyncio.wait_for(
                rec.batch_run_robust_rec(7, _dealer_vector(1, polynomials)),
                timeout=0.2,
            )

        self.assertEqual([int(value) for value in values], [13, 23])
        self.assertTrue(any(not task.done() for task in rec.tasks))

        live_tasks = list(rec.tasks)
        subscriber = rec.subscribe_recv_task
        rec.kill()
        await asyncio.gather(*live_tasks, subscriber, return_exceptions=True)

    async def test_explicit_instance_tags_are_stable_under_concurrency(self):
        rec = _make_rec(n=4, t=1, my_id=0)
        serializer = Serial(G1)
        cases = {
            "dealer-2:phase-random": [(19, 3)],
            "dealer-0:phase-tau": [(37, 5)],
        }
        payloads = {
            instance: [
                bytes(serializer.serialize_fs(
                    _dealer_vector(dealer, polynomials)
                ))
                for dealer in range(rec.n)
            ]
            for instance, polynomials in cases.items()
        }
        seen_tags = set()

        async def fake_rbc(
            sid, _pid, _n, _f, leader, predicate, rbc_input, output,
            _send, _receive, _member_list,
        ):
            seen_tags.add(sid)
            instance = sid.split(":RR.RR:dealer-", 1)[0]
            payload = rbc_input if leader == rec.my_id else payloads[instance][leader]
            if await predicate(payload):
                output(payload)

        async def reconstruct(instance):
            local = _dealer_vector(rec.my_id, cases[instance])
            return await rec.batch_run_robust_rec(
                "shared-phase-name", local, instance_id=instance
            )

        with patch("adkg.robust_rec.optqrbc_dynamic", new=fake_rbc):
            results = await asyncio.wait_for(
                asyncio.gather(*[
                    reconstruct("dealer-0:phase-tau"),
                    reconstruct("dealer-2:phase-random"),
                ]),
                timeout=0.2,
            )

        self.assertEqual(
            [[int(value) for value in result] for result in results],
            [[37], [19]],
        )
        self.assertEqual(seen_tags, {
            f"{instance}:RR.RR:dealer-{dealer}"
            for instance in cases
            for dealer in range(rec.n)
        })

        live_tasks = list(rec.tasks)
        subscriber = rec.subscribe_recv_task
        rec.kill()
        await asyncio.gather(*live_tasks, subscriber, return_exceptions=True)

    async def test_real_rbc_network_terminates_with_one_omitted_party(self):
        n, t = 4, 1
        network = [asyncio.Queue() for _ in range(n)]
        polynomials = [(31, 6), (47, 10)]
        active_dealers = (1, 2, 3)
        recs = []

        for party in active_dealers:
            def send(destination, message, sender=party):
                network[destination].put_nowait((sender, message))

            recs.append(Robust_Rec(
                [None] * n,
                None,
                None,
                None,
                n,
                t,
                t,
                party,
                send,
                network[party].get,
                None,
                (ZR, G1, multiexp, dotprod),
            ))

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*[
                    rec.batch_run_robust_rec(
                        11, _dealer_vector(rec.my_id, polynomials)
                    )
                    for rec in recs
                ]),
                timeout=1,
            )
            self.assertEqual(
                [[int(value) for value in result] for result in results],
                [[31, 47]] * len(active_dealers),
            )
        finally:
            cleanup = []
            for rec in recs:
                cleanup.extend(list(rec.tasks))
                cleanup.append(rec.subscribe_recv_task)
                rec.kill()
            await asyncio.gather(*cleanup, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
