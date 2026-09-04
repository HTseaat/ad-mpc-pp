import copy
from ctypes import CDLL, c_bool, c_char_p, c_int, c_void_p, string_at
import json
from pathlib import Path
import unittest

from beaver.aggtrans_commitment_fork import FIELD_ORDER
from beaver.batchmul_input_commitment_fork import (
    build_batchmul_input_commitment_fork,
)


class BatchMulInputCommitmentForkTests(unittest.TestCase):
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
        cls.lib.pyMultiplyClaimedValuesWithAux.argtypes = [c_char_p, c_char_p]
        cls.lib.pyMultiplyClaimedValuesWithAux.restype = c_char_p

        cls.bp = CDLL(str(root / "libbulletproofs_amcl.so"))
        cls.bp.pyProveFactors.argtypes = [c_char_p]
        cls.bp.pyProveFactors.restype = c_void_p
        cls.bp.pyVerifyFactors.argtypes = [c_char_p]
        cls.bp.pyVerifyFactors.restype = c_void_p
        cls.bp.pyFreeString.argtypes = [c_void_p]
        cls.bp.pyFreeString.restype = None

        cls.n = 4
        cls.t = 1
        cls.lib.pySetN(cls.n)
        cls.srs = json.loads(cls.lib.pyNewSRS(cls.t).decode("utf-8"))
        cls.pk = json.dumps(cls.srs["Pk"]).encode("utf-8")
        cls.vk = json.dumps(cls.srs["Vk"]).encode("utf-8")
        cls.left = json.loads(
            cls.lib.pyCommit(
                cls.pk, json.dumps(["17", "23"]).encode("utf-8"), cls.t
            ).decode("utf-8")
        )
        cls.right = json.loads(
            cls.lib.pyCommit(
                cls.pk, json.dumps(["5", "7"]).encode("utf-8"), cls.t
            ).decode("utf-8")
        )

    def _payload(self, committed, dealer):
        return {
            "commitment": copy.deepcopy(committed["commitmentList"]),
            "proof": copy.deepcopy(committed["batchproofsofallparties"][dealer]),
        }

    def _fork(self, dealer=3):
        left = self._payload(self.left, dealer)
        right = self._payload(self.right, dealer)
        forked_left, forked_right = build_batchmul_input_commitment_fork(
            kzg_lib=self.lib,
            srs_pk=self.pk,
            left_payload=left,
            right_payload=right,
            n=self.n,
            dealer_local_id=dealer,
            attack_index=0,
            delta=1,
        )
        return left, right, forked_left, forked_right

    def test_both_inputs_shift_without_mutating_originals(self):
        left, right, forked_left, forked_right = self._fork()
        for original, forked in ((left, forked_left), (right, forked_right)):
            self.assertEqual(
                int(forked["proof"][0]["ClaimedValue"]),
                (int(original["proof"][0]["ClaimedValue"]) + 1) % FIELD_ORDER,
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
                    3,
                )
            )
            self.assertFalse(
                self.lib.pyBatchVerify(
                    self.vk,
                    json.dumps(original["commitment"]).encode("utf-8"),
                    json.dumps(forked["proof"]).encode("utf-8"),
                    3,
                )
            )
        self.assertEqual(left, self._payload(self.left, 3))
        self.assertEqual(right, self._payload(self.right, 3))

    def test_corrupted_dealers_share_the_same_alternate_input_view(self):
        views = []
        for dealer in (2, 3):
            _, _, forked_left, forked_right = self._fork(dealer)
            views.append((forked_left["commitment"], forked_right["commitment"]))
        self.assertEqual(views[0], views[1])

    def test_recomputed_product_has_a_valid_factor_proof(self):
        _, _, left, right = self._fork()
        left_proofs = left["proof"]
        right_proofs = right["proof"]
        result = json.loads(
            self.lib.pyMultiplyClaimedValuesWithAux(
                json.dumps(left_proofs).encode("utf-8"),
                json.dumps(right_proofs).encode("utf-8"),
            ).decode("utf-8")
        )

        left_values = [int(item["ClaimedValue"]) for item in left_proofs]
        right_values = [int(item["ClaimedValue"]) for item in right_proofs]
        left_aux = [int(item["ClaimedValueAux"]) for item in left_proofs]
        right_aux = [int(item["ClaimedValueAux"]) for item in right_proofs]
        output_values = [int(value) for value in result["value"]]
        output_aux = [int(value) for value in result["aux"]]
        self.assertEqual(
            output_values[0], left_values[0] * right_values[0] % FIELD_ORDER
        )

        pk_dict = self.srs["Pk"]
        g0, h0 = pk_dict["G1_g"][0], pk_dict["G1_h"][0]
        g_hex = (
            b"\x04"
            + int(g0["X"]).to_bytes(48, "big")
            + int(g0["Y"]).to_bytes(48, "big")
        ).hex()
        h_hex = (
            b"\x04"
            + int(h0["X"]).to_bytes(48, "big")
            + int(h0["Y"]).to_bytes(48, "big")
        ).hex()
        witnesses = []
        for p, q, r, p_blind, q_blind, r_blind in zip(
            left_values,
            right_values,
            output_values,
            left_aux,
            right_aux,
            output_aux,
        ):
            witnesses.append(
                {
                    "p": hex(p)[2:],
                    "q": hex(q)[2:],
                    "r": hex(r)[2:],
                    "p_blind": hex(p_blind)[2:],
                    "q_blind": hex(q_blind)[2:],
                    "r_blind": hex(r_blind)[2:],
                }
            )
        proof_ptr = self.bp.pyProveFactors(
            json.dumps({"witnesses": witnesses, "g": g_hex, "h": h_hex}).encode(
                "utf-8"
            )
        )
        try:
            proof = json.loads(string_at(proof_ptr).decode("utf-8"))["proof"]
        finally:
            self.bp.pyFreeString(proof_ptr)

        pedersen_vectors = []
        for values, aux in (
            (left_values, left_aux),
            (right_values, right_aux),
            (output_values, output_aux),
        ):
            pedersen_vectors.append(
                json.loads(
                    self.lib.pyPedersenCommit(
                        self.pk,
                        json.dumps([str(value) for value in values]).encode("utf-8"),
                        json.dumps([str(value) for value in aux]).encode("utf-8"),
                    ).decode("utf-8")
                )
            )
        commitments = []
        for index in range(len(left_values)):
            for vector in pedersen_vectors:
                point = vector[index]
                commitments.append(
                    f"({int(point['X']):096X},{int(point['Y']):096X})"
                )
        verify_ptr = self.bp.pyVerifyFactors(
            json.dumps(
                {
                    "proof": proof,
                    "commitments": commitments,
                    "g": g_hex,
                    "h": h_hex,
                }
            ).encode("utf-8")
        )
        try:
            verified = json.loads(string_at(verify_ptr).decode("utf-8"))["verified"]
        finally:
            self.bp.pyFreeString(verify_ptr)
        self.assertTrue(verified)


if __name__ == "__main__":
    unittest.main()
