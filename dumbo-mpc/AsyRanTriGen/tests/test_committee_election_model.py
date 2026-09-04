import hashlib
import os
import subprocess
import sys
import unittest

from committee_election.model import (
    CandidateCommittee,
    CandidateRegistry,
    CommitteeMember,
    ElectionContext,
    ElectionModelError,
    derive_coin_seed,
    deterministic_permutation,
    select_candidate,
)


def digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def make_registry(candidate_count=4, committee_size=4, reverse=False):
    candidates = []
    for candidate_index in range(candidate_count):
        members = []
        for local_id in range(committee_size):
            global_id = candidate_index * committee_size + local_id
            members.append(
                CommitteeMember(
                    global_party_id=global_id,
                    endpoint_id=f"localhost:{10000 + global_id}",
                    authenticated_identity_digest=digest(f"auth-{global_id}"),
                    protocol_public_key_digest=digest(f"pk-{global_id}"),
                )
            )
        if reverse:
            members.reverse()
        candidates.append(
            CandidateCommittee(f"candidate-{candidate_index:02d}", tuple(members))
        )
    if reverse:
        candidates.reverse()
    return CandidateRegistry("registry-test", committee_size, tuple(candidates))


class CandidateRegistryTests(unittest.TestCase):
    def test_input_order_does_not_change_canonical_registry(self):
        normal = make_registry()
        reversed_registry = make_registry(reverse=True)
        self.assertEqual(normal.canonical_bytes(), reversed_registry.canonical_bytes())
        self.assertEqual(normal.digest(), reversed_registry.digest())

    def test_json_round_trip_is_canonical(self):
        registry = make_registry()
        decoded = CandidateRegistry.from_json_bytes(registry.canonical_bytes())
        self.assertEqual(decoded, registry)
        self.assertEqual(decoded.canonical_bytes(), registry.canonical_bytes())

    def test_duplicate_candidate_rejected(self):
        registry = make_registry()
        with self.assertRaises(ElectionModelError):
            CandidateRegistry(
                registry.registry_id,
                registry.committee_size,
                (registry.candidates[0], registry.candidates[0]),
            )

    def test_duplicate_member_and_endpoint_rejected(self):
        member = make_registry().candidates[0].members[0]
        with self.assertRaises(ElectionModelError):
            CandidateCommittee("bad", (member, member))

    def test_wrong_committee_size_and_empty_registry_rejected(self):
        registry = make_registry()
        with self.assertRaises(ElectionModelError):
            CandidateRegistry("bad", 5, registry.candidates)
        with self.assertRaises(ElectionModelError):
            CandidateRegistry("bad", 4, ())

    def test_unknown_schema_fields_rejected(self):
        value = make_registry().to_dict()
        value["unexpected"] = True
        with self.assertRaises(ElectionModelError):
            CandidateRegistry.from_dict(value)

    def test_boolean_registry_and_message_versions_are_rejected(self):
        value = make_registry().to_dict()
        value["registry_version"] = True
        with self.assertRaises(ElectionModelError):
            CandidateRegistry.from_dict(value)
        registry = make_registry()
        context = ElectionContext.for_registry(
            run_id="run", source_committee_id="P1", target_epoch=2,
            registry=registry,
        )
        with self.assertRaises(ElectionModelError):
            ElectionContext(**dict(context.to_dict(), message_version=True))

    def test_endpoint_or_key_change_changes_digest(self):
        original = make_registry()
        value = original.to_dict()
        value["candidates"][0]["members"][0]["endpoint_id"] = "localhost:20000"
        changed_endpoint = CandidateRegistry.from_dict(value)
        self.assertNotEqual(original.digest(), changed_endpoint.digest())
        value = original.to_dict()
        value["candidates"][0]["members"][0][
            "protocol_public_key_digest"
        ] = digest("changed")
        changed_key = CandidateRegistry.from_dict(value)
        self.assertNotEqual(original.digest(), changed_key.digest())


class ElectionMessageAndSelectionTests(unittest.TestCase):
    def setUp(self):
        self.registry = make_registry()
        self.context = ElectionContext.for_registry(
            run_id="run-001",
            source_committee_id="P1",
            target_epoch=2,
            registry=self.registry,
        )

    def test_context_binds_run_source_target_and_registry(self):
        baseline = self.context.canonical_bytes()
        changes = [
            dict(run_id="run-002"),
            dict(source_committee_id="P0"),
            dict(target_epoch=3),
            dict(registry_digest=digest("other-registry")),
        ]
        for change in changes:
            values = self.context.to_dict()
            values.update(change)
            self.assertNotEqual(ElectionContext(**values).canonical_bytes(), baseline)

    def test_context_rejects_bootstrap_epoch_one(self):
        with self.assertRaises(ElectionModelError):
            ElectionContext.for_registry(
                run_id="run", source_committee_id="P0", target_epoch=1,
                registry=self.registry,
            )

    def test_fixed_selection_vectors_for_multiple_candidate_counts(self):
        seed = bytes(range(32))
        vectors = {}
        for count in (1, 2, 3, 4, 16):
            result = select_candidate(seed, make_registry(candidate_count=count))
            vectors[count] = (result.candidate_index, result.selection_counter)
        self.assertEqual(
            vectors,
            {1: (0, 0), 2: (1, 0), 3: (1, 0), 4: (3, 0), 16: (11, 0)},
        )

    def test_full_width_coin_seed_vector(self):
        seed = derive_coin_seed(b"signature-vector")
        self.assertEqual(len(seed), 32)
        self.assertEqual(
            seed.hex(),
            "f524472bdf9f85017f3709bdc747578b4e42523225da014d07b91f171c73d504",
        )

    def test_deterministic_permutation_is_complete_and_stable(self):
        seed = digest("permutation-seed")
        first = deterministic_permutation(bytes.fromhex(seed), 16)
        second = deterministic_permutation(bytes.fromhex(seed), 16)
        self.assertEqual(first, second)
        self.assertEqual(sorted(first), list(range(16)))

    def test_selection_rejects_bad_seed_and_bounds(self):
        with self.assertRaises(ElectionModelError):
            select_candidate(b"short", self.registry)
        with self.assertRaises(ElectionModelError):
            deterministic_permutation(bytes(32), 0)

    def test_canonical_message_is_stable_across_hash_seeds(self):
        script = (
            "from tests.test_committee_election_model import make_registry;"
            "from committee_election.model import ElectionContext,select_candidate;"
            "r=make_registry(reverse=True);"
            "c=ElectionContext.for_registry(run_id='run-001',"
            "source_committee_id='P1',target_epoch=2,registry=r);"
            "s=select_candidate(bytes(range(32)),r);"
            "print(c.canonical_bytes().hex(),s.candidate_index,s.selection_counter)"
        )
        outputs = []
        for hash_seed in ("1", "987654"):
            env = dict(os.environ, PYTHONHASHSEED=hash_seed)
            outputs.append(
                subprocess.check_output([sys.executable, "-c", script], env=env).strip()
            )
        self.assertEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
