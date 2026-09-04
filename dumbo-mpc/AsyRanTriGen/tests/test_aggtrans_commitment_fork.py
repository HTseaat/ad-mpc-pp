import copy
from ctypes import CDLL, c_bool, c_char_p, c_int
import json
from pathlib import Path
import unittest

from beaver.aggtrans_commitment_fork import (
    FIELD_ORDER,
    build_aggtrans_commitment_fork,
)


class AggTransCommitmentForkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.lib = CDLL(str(root / "kzg_ped_out.so"))
        cls.lib.pyNewSRS.argtypes = [c_int]
        cls.lib.pyNewSRS.restype = c_char_p
        cls.lib.pySetN.argtypes = [c_int]
        cls.lib.pySetN.restype = None
        cls.lib.pyCommit.argtypes = [c_char_p, c_char_p, c_int]
        cls.lib.pyCommit.restype = c_char_p
        cls.lib.pyPedersenCommit.argtypes = [c_char_p, c_char_p, c_char_p]
        cls.lib.pyPedersenCommit.restype = c_char_p
        cls.lib.pyCircuitAdd.argtypes = [c_char_p, c_char_p]
        cls.lib.pyCircuitAdd.restype = c_char_p
        cls.lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
        cls.lib.pyBatchVerify.restype = c_bool

        cls.n = 4
        cls.t = 1
        cls.lib.pySetN(cls.n)
        srs = json.loads(cls.lib.pyNewSRS(cls.t).decode("utf-8"))
        cls.pk = json.dumps(srs["Pk"]).encode("utf-8")
        cls.vk = json.dumps(srs["Vk"]).encode("utf-8")
        committed = json.loads(
            cls.lib.pyCommit(
                cls.pk, json.dumps(["17", "23"]).encode("utf-8"), cls.t
            ).decode("utf-8")
        )
        cls.commitments = committed["commitmentList"]
        cls.proof_matrix = committed["batchproofsofallparties"]

    def _payload(self, dealer):
        return {
            "commitment": copy.deepcopy(self.commitments),
            "proof": copy.deepcopy(self.proof_matrix[dealer]),
        }

    def test_share_plus_one_reuses_witness_and_verifies_against_fork(self):
        dealer = 3
        original = self._payload(dealer)
        untouched = copy.deepcopy(original)
        forked = build_aggtrans_commitment_fork(
            kzg_lib=self.lib,
            srs_pk=self.pk,
            payload=original,
            n=self.n,
            dealer_local_id=dealer,
            attack_index=0,
            delta=1,
        )

        self.assertEqual(original, untouched)
        self.assertEqual(
            int(forked["proof"][0]["ClaimedValue"]),
            int(original["proof"][0]["ClaimedValue"]) + 1,
        )
        self.assertEqual(forked["proof"][0]["H"], original["proof"][0]["H"])
        self.assertEqual(
            forked["proof"][0]["ClaimedValueAux"],
            original["proof"][0]["ClaimedValueAux"],
        )
        self.assertTrue(
            self.lib.pyBatchVerify(
                self.vk,
                json.dumps(forked["commitment"]).encode("utf-8"),
                json.dumps(forked["proof"]).encode("utf-8"),
                dealer,
            )
        )
        self.assertFalse(
            self.lib.pyBatchVerify(
                self.vk,
                json.dumps(original["commitment"]).encode("utf-8"),
                json.dumps(forked["proof"]).encode("utf-8"),
                dealer,
            )
        )

    def test_corrupted_dealers_derive_the_same_forked_commitment(self):
        forked_commitments = []
        for dealer in (2, 3):
            forked = build_aggtrans_commitment_fork(
                kzg_lib=self.lib,
                srs_pk=self.pk,
                payload=self._payload(dealer),
                n=self.n,
                dealer_local_id=dealer,
                attack_index=1,
                delta=1,
            )
            forked_commitments.append(forked["commitment"])
        self.assertEqual(forked_commitments[0], forked_commitments[1])
        self.assertNotEqual(forked_commitments[0], self.commitments)

    def test_auxiliary_randomness_is_compared_as_a_field_element(self):
        dealer = 3
        original = self._payload(dealer)
        original["proof"][0]["ClaimedValueAux"] = str(
            int(original["proof"][0]["ClaimedValueAux"]) + FIELD_ORDER
        )

        forked = build_aggtrans_commitment_fork(
            kzg_lib=self.lib,
            srs_pk=self.pk,
            payload=original,
            n=self.n,
            dealer_local_id=dealer,
            attack_index=0,
            delta=1,
        )

        self.assertEqual(
            int(forked["proof"][0]["ClaimedValueAux"]),
            int(original["proof"][0]["ClaimedValueAux"]) % FIELD_ORDER,
        )


if __name__ == "__main__":
    unittest.main()
