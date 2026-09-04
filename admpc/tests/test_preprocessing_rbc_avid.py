import asyncio
import unittest
from unittest.mock import patch

from adkg.acss import ACSS
from adkg.poly_commit_hybrid import PolyCommitHybrid
from adkg.symmetric_crypto import SymmetricCrypto
from pypairing import G1, ZR, blsmultiexp as multiexp


class PreprocessingSplitSerializationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the benchmark wire path with inner-proof-only evaluation."""
    async def asyncSetUp(self):
        self.n = 4
        self.t = 1
        self.g = G1.rand(b"split-g")
        self.h = G1.rand(b"split-h")
        self.private_keys = [ZR.random() for _ in range(self.n)]
        self.public_keys = [
            self.g ** private_key for private_key in self.private_keys
        ]
        self.queues = [asyncio.Queue() for _ in range(2)]
        pc = PolyCommitHybrid(self.g, self.h, ZR, multiexp)
        self.dealer = ACSS(
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
            self.queues[0].get,
            pc,
            ZR,
            G1,
        )
        self.receiver = ACSS(
            self.public_keys,
            self.private_keys[1],
            self.g,
            self.h,
            self.n,
            self.t,
            self.t,
            2,
            1,
            lambda _destination, _message: None,
            self.queues[1].get,
            pc,
            ZR,
            G1,
        )

    async def asyncTearDown(self):
        self.dealer.kill()
        self.receiver.kill()
        await asyncio.gather(
            self.dealer.subscribe_recv_task,
            self.receiver.subscribe_recv_task,
            return_exceptions=True,
        )

    def _assert_private_ciphertexts(self, public_msg, ciphertexts, ephkey,
                                    minimum_plaintext_size):
        self.assertIsInstance(public_msg, bytes)
        self.assertEqual(len(ciphertexts), self.n)
        self.assertTrue(all(isinstance(item, bytes) for item in ciphertexts))
        self.assertTrue(all(item not in public_msg for item in ciphertexts))

        for receiver_id, ciphertext in enumerate(ciphertexts):
            shared_key = ephkey ** self.private_keys[receiver_id]
            plaintext = SymmetricCrypto.decrypt(
                shared_key.__getstate__(), ciphertext
            )
            self.assertGreater(len(plaintext), minimum_plaintext_size)

    def _tamper_first_share(self, ciphertext, ephkey, poly_num):
        shared_key = ephkey ** self.private_keys[1]
        plaintext = SymmetricCrypto.decrypt(
            shared_key.__getstate__(), ciphertext
        )
        phis_bytes_len = poly_num * self.receiver.sr.f_size
        phis = self.receiver.sr.deserialize_fs(plaintext[:phis_bytes_len])
        phis[0] += ZR(1)
        tampered_plaintext = bytes(
            self.receiver.sr.serialize_fs(phis)
        ) + plaintext[phis_bytes_len:]
        return SymmetricCrypto.encrypt(
            shared_key.__getstate__(), tampered_plaintext
        )

    async def test_batchrand_uses_public_rbc_and_n_private_avid_items(self):
        values = [ZR.random() for _ in range(3)]
        public_msg, ciphertexts = self.dealer._get_dealer_msg(
            values, self.n, separate=True
        )

        commits, shared, ephkey = self.receiver.decode_public_log(
            public_msg, len(values)
        )
        self.assertEqual(len(commits), len(values))
        self.assertEqual(len(shared[3]), len(values))
        self._assert_private_ciphertexts(
            public_msg,
            ciphertexts,
            ephkey,
            len(values) * self.receiver.sr.f_size,
        )
        high_dealer_id = 3
        self.assertTrue(self.receiver._decode_and_verify_split_log_sync(
            high_dealer_id, public_msg, ciphertexts[1], len(values)
        ))
        self.receiver.data.pop(high_dealer_id)
        tampered_ciphertext = self._tamper_first_share(
            ciphertexts[1], ephkey, len(values)
        )
        verify_evaluation = self.receiver.poly_commit_log.batch_verify_eval_rs
        with patch.object(
            self.receiver.poly_commit_log,
            "batch_verify_eval_rs",
            wraps=verify_evaluation,
        ) as verify_evaluation:
            self.assertTrue(self.receiver._decode_and_verify_split_log_sync(
                high_dealer_id, public_msg, tampered_ciphertext, len(values)
            ))
        verify_evaluation.assert_called_once()
        self.assertTrue(self.receiver.acss_status[high_dealer_id])
        self.assertIn(high_dealer_id, self.receiver.data)

        self.assertFalse(self.receiver._decode_and_verify_split_log_sync(
            high_dealer_id, public_msg, ciphertexts[0], len(values)
        ))

        with self.assertRaises(ValueError):
            self.receiver.decode_public_log(
                public_msg + ciphertexts[0], len(values)
            )

    async def test_batchbundle_keeps_sigma_proof_public(self):
        values = [ZR.random() for _ in range(4)]
        public_msg, ciphertexts = self.dealer._get_dealer_msg_bundle(
            values, self.n, separate=True
        )

        commits, shared, ephkey, proof_tuple, w_list = (
            self.receiver.decode_public_bundle_log(public_msg, len(values))
        )
        self.assertEqual(len(commits), len(values))
        self.assertEqual(len(shared[3]), len(values))
        self.assertEqual(len(w_list), len(values) // 2)
        self.assertEqual(len(proof_tuple[0]), len(values) // 2)
        self._assert_private_ciphertexts(
            public_msg,
            ciphertexts,
            ephkey,
            len(values) * self.receiver.sr.f_size,
        )
        high_dealer_id = 3
        self.assertTrue(
            self.receiver._decode_and_verify_split_bundle_log_sync(
                high_dealer_id, public_msg, ciphertexts[1], len(values)
            )
        )
        self.receiver.data.pop(high_dealer_id)
        tampered_ciphertext = self._tamper_first_share(
            ciphertexts[1], ephkey, len(values)
        )
        verify_evaluation = self.receiver.poly_commit_log.batch_verify_eval_rs
        with patch.object(
            self.receiver.poly_commit_log,
            "batch_verify_eval_rs",
            wraps=verify_evaluation,
        ) as verify_evaluation:
            self.assertTrue(
                self.receiver._decode_and_verify_split_bundle_log_sync(
                    high_dealer_id, public_msg, tampered_ciphertext,
                    len(values)
                )
            )
        verify_evaluation.assert_called_once()
        self.assertTrue(self.receiver.acss_status[high_dealer_id])
        self.assertIn(high_dealer_id, self.receiver.data)

        with self.assertRaises(ValueError):
            self.receiver.decode_public_bundle_log(
                public_msg[:-1], len(values)
            )
        with self.assertRaises(ValueError):
            self.receiver.decode_public_bundle_log(public_msg, 3)

    async def test_adprep_uses_six_cm_public_commitments(self):
        cm = 2
        multiplication_triples = []
        check_triples = []
        for _ in range(cm):
            left, right = ZR.random(), ZR.random()
            multiplication_triples.append([left, right, left * right])
            check_left, check_right = ZR.random(), ZR.random()
            check_triples.append([
                check_left, check_right, check_left * check_right
            ])

        public_msg, ciphertexts = self.dealer._get_dealer_msg_aprep(
            (multiplication_triples, check_triples, cm),
            self.n,
            separate=True,
        )
        poly_num = 6 * cm
        commits, shared, ephkey = self.receiver.decode_public_log(
            public_msg, poly_num
        )
        self.assertEqual(len(commits), poly_num)
        self.assertEqual(len(shared[3]), poly_num)
        self._assert_private_ciphertexts(
            public_msg,
            ciphertexts,
            ephkey,
            poly_num * self.receiver.sr.f_size,
        )
        high_dealer_id = 3
        self.assertTrue(self.receiver._decode_and_verify_split_log_sync(
            high_dealer_id, public_msg, ciphertexts[1], poly_num
        ))
        self.receiver.data.pop(high_dealer_id)
        tampered_ciphertext = self._tamper_first_share(
            ciphertexts[1], ephkey, poly_num
        )
        verify_evaluation = self.receiver.poly_commit_log.batch_verify_eval_rs
        with patch.object(
            self.receiver.poly_commit_log,
            "batch_verify_eval_rs",
            wraps=verify_evaluation,
        ) as verify_evaluation:
            self.assertTrue(self.receiver._decode_and_verify_split_log_sync(
                high_dealer_id, public_msg, tampered_ciphertext, poly_num
            ))
        verify_evaluation.assert_called_once()
        self.assertTrue(self.receiver.acss_status[high_dealer_id])
        self.assertIn(high_dealer_id, self.receiver.data)

        with self.assertRaises(ValueError):
            self.receiver.decode_public_log(public_msg, poly_num - 1)

    async def test_legacy_static_rand_wire_format_is_preserved(self):
        values = [ZR.random() for _ in range(2)]
        legacy_proposal = self.dealer._get_dealer_msg(values, self.n)

        self.assertIsInstance(legacy_proposal, bytes)
        self.assertTrue(self.receiver._decode_and_verify_log_sync(
            0, legacy_proposal, len(values)
        ))

    async def test_dynamic_member_order_is_source_then_destination(self):
        self.assertEqual(
            self.dealer._dynamic_bacss_members(3, 2),
            [10, 12, 13, 14, 15],
        )


if __name__ == "__main__":
    unittest.main()
