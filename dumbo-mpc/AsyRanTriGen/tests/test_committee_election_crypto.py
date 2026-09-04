import base64
from dataclasses import replace
import itertools
import unittest

from beaver.broadcast.crypto.boldyreva import dealer
from committee_election.crypto import (
    ElectionCertificate,
    ElectionCryptoError,
    build_certificate,
    sign_share,
    validate_public_key,
    verify_certificate,
    verify_share,
)
from committee_election.model import ElectionContext
from tests.test_committee_election_model import make_registry


class ThresholdElectionCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = make_registry()
        cls.context = ElectionContext.for_registry(
            run_id="crypto-run",
            source_committee_id="P1",
            target_epoch=2,
            registry=cls.registry,
        )
        cls.pk4, cls.sks4 = dealer(4, 2, seed=100)

    def shares(self, pk=None, sks=None, context=None):
        pk = pk or self.pk4
        sks = sks or self.sks4
        context = context or self.context
        return {
            sender: sign_share(sk, pk, sender, context)[0]
            for sender, sk in enumerate(sks)
        }

    def test_existing_key_threshold_is_t_plus_one(self):
        validate_public_key(self.pk4, n=4, t=1)
        self.assertEqual(self.pk4.l, 4)
        self.assertEqual(self.pk4.k, 2)
        with self.assertRaises(ElectionCryptoError):
            validate_public_key(self.pk4, n=4, t=2)

    def test_all_n4_threshold_subsets_produce_unique_output(self):
        shares = self.shares()
        signatures = set()
        selections = set()
        for subset in itertools.combinations(range(4), 2):
            certificate, used, _ = build_certificate(
                public_key=self.pk4,
                registry=self.registry,
                context=self.context,
                shares={sender: shares[sender] for sender in subset},
            )
            resolved, _ = verify_certificate(
                public_key=self.pk4,
                registry=self.registry,
                certificate=certificate,
            )
            signatures.add(certificate.signature_digest)
            selections.add((resolved.selection.candidate_index, resolved.committee.committee_id))
            self.assertEqual(used, subset)
            self.assertEqual(certificate.signer_ids, subset)
        self.assertEqual(len(signatures), 1)
        self.assertEqual(len(selections), 1)

    def test_multiple_n10_subsets_produce_unique_output(self):
        pk, sks = dealer(10, 4, seed=200)
        registry = make_registry(candidate_count=8, committee_size=10)
        context = ElectionContext.for_registry(
            run_id="n10", source_committee_id="P1", target_epoch=2,
            registry=registry,
        )
        shares = self.shares(pk, sks, context)
        subsets = ((0, 1, 2, 3), (1, 4, 7, 9), (2, 5, 6, 8))
        outputs = set()
        for subset in subsets:
            certificate, _, _ = build_certificate(
                public_key=pk, registry=registry, context=context,
                shares={sender: shares[sender] for sender in subset},
            )
            outputs.add((certificate.signature_digest, certificate.committee_id))
        self.assertEqual(len(outputs), 1)

    def test_wrong_sender_and_wrong_message_share_rejected(self):
        shares = self.shares()
        valid, _ = verify_share(self.pk4, 1, self.context, shares[0])
        self.assertFalse(valid)
        other_context = replace(self.context, target_epoch=3)
        wrong_message_share = sign_share(
            self.sks4[0], self.pk4, 0, other_context
        )[0]
        valid, _ = verify_share(self.pk4, 0, self.context, wrong_message_share)
        self.assertFalse(valid)

    def test_less_than_threshold_and_mismatched_private_index_rejected(self):
        shares = self.shares()
        with self.assertRaises(ElectionCryptoError):
            build_certificate(
                public_key=self.pk4, registry=self.registry, context=self.context,
                shares={0: shares[0]},
            )
        with self.assertRaises(ElectionCryptoError):
            sign_share(self.sks4[0], self.pk4, 1, self.context)

    def test_tampered_certificate_fields_rejected(self):
        shares = self.shares()
        certificate, _, _ = build_certificate(
            public_key=self.pk4, registry=self.registry, context=self.context,
            shares={0: shares[0], 1: shares[1]},
        )
        mutations = [
            replace(certificate, committee_id="not-selected"),
            replace(certificate, candidate_index=(certificate.candidate_index + 1) % 4),
            replace(certificate, selection_counter=certificate.selection_counter + 1),
            replace(certificate, registry_digest="0" * 64),
            replace(certificate, target_epoch=3),
            replace(certificate, signature_digest="0" * 64),
            replace(certificate, signer_ids=(0, 0)),
            replace(certificate, signer_ids=(0, 4)),
            replace(certificate, certificate_version=True),
            replace(certificate, selection_counter=True),
            replace(certificate, candidate_index=False),
            replace(certificate, threshold_signature_b64=base64.b64encode(b"bad").decode()),
        ]
        for mutation in mutations:
            with self.assertRaises(ElectionCryptoError):
                verify_certificate(
                    public_key=self.pk4,
                    registry=self.registry,
                    certificate=mutation,
                )

    def test_certificate_schema_round_trip_and_unknown_field_rejection(self):
        shares = self.shares()
        certificate, _, _ = build_certificate(
            public_key=self.pk4, registry=self.registry, context=self.context,
            shares={0: shares[0], 2: shares[2]},
        )
        decoded = ElectionCertificate.from_dict(certificate.to_dict())
        self.assertEqual(decoded.canonical_bytes(), certificate.canonical_bytes())
        value = certificate.to_dict()
        value["unexpected"] = True
        with self.assertRaises(ElectionCryptoError):
            ElectionCertificate.from_dict(value)

    def test_breakdown_is_machine_readable_and_nonnegative(self):
        shares = self.shares()
        _, _, breakdown = build_certificate(
            public_key=self.pk4, registry=self.registry, context=self.context,
            shares={0: shares[0], 1: shares[1]},
        )
        self.assertEqual(
            set(breakdown.to_dict()),
            {"share_verify_ms_total", "combine_ms", "combined_verify_ms", "selection_ms"},
        )
        self.assertTrue(all(value >= 0 for value in breakdown.to_dict().values()))


if __name__ == "__main__":
    unittest.main()
