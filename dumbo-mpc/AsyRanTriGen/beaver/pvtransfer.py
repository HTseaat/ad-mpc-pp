import logging
import asyncio
from beaver.broadcast.otmvba import OptimalCommonSet
from beaver.utils.misc import wrap_send, subscribe_recv
import time
from ctypes import *
import json
import sys
from beaver.tob import YosoTOB
import base64
from Crypto.Util.number import long_to_bytes


from dataclasses import dataclass, asdict
from typing import List, Tuple, Dict

# ---------------------------------------------------------------------------
#  Data classes for packaging PV‑Transfer artefacts through RBC / TOB
# ---------------------------------------------------------------------------

@dataclass
class EncResult:
    """Per‑recipient encryption artefacts produced in PV‑Transfer."""
    node_id: int
    pk: str
    C1: str
    C2: str
    cipher_shares: List[Tuple[str, str]]          # list of (c, c′) scalars, hex
    W: List[str]                                  # list of uncompressed‑hex G1 points
    proof: str                                    # Bulletproof proof, hex‑encoded


@dataclass
class PVTransferPayload:
    """
    Bundle shipped through ΠGather / ΠRBC / ΠTOB for one PV‑Transfer round.

    Use `to_bytes()` before sending over the network, and `from_bytes()` on
    reception to recover the structured object.
    """
    dealer_id: int
    enc_results: List[EncResult]
    commitment: str
    agg_proof_at_zero: str
    aggregated_proof_list: List[str]
    agg_secrets_commitment: str

    # ---- Serialization helpers ---------------------------------------------
    def to_bytes(self) -> bytes:
        """Serialize to UTF‑8 JSON bytes suitable for RBC / TOB broadcast."""
        return json.dumps(asdict(self), separators=(",", ":")).encode()

    @staticmethod
    def from_bytes(data: bytes) -> "PVTransferPayload":
        obj = json.loads(data.decode())
        obj["enc_results"] = [EncResult(**er) for er in obj["enc_results"]]
        return PVTransferPayload(**obj)

lib_bulletproof = CDLL("./libbulletproofs_amcl.so")

lib_bulletproof.pyProveFactors.argtypes = [c_char_p]
# lib_bulletproof.pyProveFactors.restype = c_char_p
lib_bulletproof.pyProveFactors.restype = c_void_p

# lib_bulletproof.pyFreeString.argtypes = [c_char_p]
lib_bulletproof.pyFreeString.argtypes = [c_void_p]  # ✅ 必须匹配！
lib_bulletproof.pyFreeString.restype = None

lib_bulletproof.pyVerifyFactors.argtypes = [c_char_p]
# lib_bulletproof.pyVerifyFactors.restype = 
lib_bulletproof.pyVerifyFactors.restype = c_void_p  # ✅ 正确类型！

lib_bulletproof.pyElGamalEncrypt.argtypes = [c_char_p]
lib_bulletproof.pyElGamalEncrypt.restype = c_void_p

lib_bulletproof.pyElGamalDecrypt.argtypes = [c_char_p]
lib_bulletproof.pyElGamalDecrypt.restype = c_void_p

lib_bulletproof.pyProveFull.argtypes = [c_char_p]
lib_bulletproof.pyProveFull.restype = c_void_p

lib_bulletproof.pyVerifyFull.argtypes = [c_char_p]
lib_bulletproof.pyVerifyFull.restype = c_void_p

lib_bulletproof.pyComputeCommitmentGH.argtypes = [c_char_p]
lib_bulletproof.pyComputeCommitmentGH.restype = c_void_p

lib_bulletproof.pySymEncrypt.argtypes = [c_char_p]
lib_bulletproof.pySymEncrypt.restype = c_void_p

lib_bulletproof.pySymDecrypt.argtypes = [c_char_p]
lib_bulletproof.pySymDecrypt.restype = c_void_p


lib = CDLL("./kzg_ped_out.so")

lib.pyCommit.argtypes = [c_char_p, c_char_p, c_int]
lib.pyCommit.restype = c_char_p
lib.pyCommitWithZeroFull.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyCommitWithZeroFull.restype  = c_char_p

lib.pyKeyEphemeralGen.argtypes = [c_char_p]
lib.pyKeyEphemeralGen.restype = c_char_p

lib.pySharedKeysGen_sender.argtypes = [c_char_p, c_char_p]
lib.pySharedKeysGen_sender.restype = c_char_p

lib.pySharedKeysGen_recv.argtypes = [c_char_p, c_char_p]
lib.pySharedKeysGen_recv.restype = c_char_p

lib.pyBatchVerify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerify.restype = c_bool

# Public verifier for KZG opening proofs (uses OpeningProofPub JSON format)
lib.pyBatchVerifyPub.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchVerifyPub.restype = c_bool

lib.pyParseRandom.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
lib.pyParseRandom.restype = c_char_p

lib.pyBatchhiddenverify.argtypes = [c_char_p, c_char_p, c_char_p, c_int]
lib.pyBatchhiddenverify.restype = c_bool

lib.pyBatchhiddenzeroverify.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyBatchhiddenzeroverify.restype = c_bool

lib.pyProdverify.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p]
lib.pyProdverify.restype = c_bool

lib.pyMultiplyClaimedValuesWithAux.argtypes = [c_char_p, c_char_p]
lib.pyMultiplyClaimedValuesWithAux.restype = c_char_p

lib.pyPedersenCommit.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyPedersenCommit.restype = c_char_p

lib.pyComputeShareGH.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyComputeShareGH.restype = c_char_p

lib.pyPedersenCombine.argtypes = [c_char_p, c_char_p]
lib.pyPedersenCombine.restype = c_char_p

lib.pyDeriveChallenge.argtypes = [c_char_p]
lib.pyDeriveChallenge.restype = c_char_p

lib.pyAggProveEvalZero.argtypes = [c_char_p, c_char_p]
lib.pyAggProveEvalZero.restype = c_char_p

lib.pyPubAggVerifyEval.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyPubAggVerifyEval.restype = c_bool

lib.pyPubAggVerifyEvalCombined.argtypes = [c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int]
lib.pyPubAggVerifyEvalCombined.restype = c_bool

lib.pyInterpolateShareswithTransfer.argtypes = [c_char_p, c_char_p, c_char_p]
lib.pyInterpolateShareswithTransfer.restype  = c_char_p


class DynamicTransferMsg:
    ACSS = "DT_ACSS"
    ACS  = "DT_ACS"

class DynamicPVTransfer:
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,                    # I/O
                 batchsize,                     # B secrets
                 init_comandproofs):                   # list of KZG commitments C_k^l, local secret shares [s_k^l],evaluation proofs [w_k^l]

        
        global logger 
        logfile = f'./log/logs-{my_id}.log'

        logging.basicConfig(
            level=logging.INFO,
            format = '%(asctime)s:[%(filename)s:%(lineno)s]:[%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile,  
            filemode='w'
        )

        logger= logging.getLogger(__name__)

        self.public_keys, self.private_key, self.pkbls, self.skbls = (public_keys, private_key, pkbls, skbls)
        self.n, self.t, self.srs, self.my_id = (n, t, srs, my_id)
        self.send, self.recv = (send, recv)
        # Create a mechanism to split the `recv` channels based on `tag`
        self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        self.batchsize = batchsize

        # Algorithm 1 inputs
        self.initial_comandproofs = init_comandproofs          

        # Create a mechanism to split the `send` channels based on `tag`
        def _send(tag):
            return wrap_send(tag, send)
        self.get_send = _send
        self.output_queue = asyncio.Queue()

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

    # ------------------------------------------------------------------
    #  Helper: local processing for PV‑Transfer (Lines 101‑109 of paper)
    # ------------------------------------------------------------------
    def _prepare_pvtransfer(self, values):
        """
        Build the PV‑Transfer payload (enc_results, commitment, aggregated
        proofs, ...) and store it in `self.pvtransfer_bytes`.
        This logic was originally inside hbacss.py.  It uses:
            • `values`    – original com+proof JSON from caller
            • self.public_keys, self.srs, ...
        """
        # ---- ①  Parse dealer's Com+Proof object -----------------------
        if isinstance(values, bytes):
            values_str = values.decode("utf-8")
        else:
            values_str = str(values)
        try:
            com_and_proof_obj = json.loads(values_str)
        except json.JSONDecodeError:
            com_and_proof_obj = json.loads(values_str.replace("'", '"'))

        proofs_lst = com_and_proof_obj.get("proof", [])
        secrets     = [p["ClaimedValue"]     for p in proofs_lst]
        secrets_aux = [p["ClaimedValueAux"]  for p in proofs_lst]

        original_commitment       = com_and_proof_obj.get("commitment", [])
        serialized_original_commitment = json.dumps(original_commitment).encode("utf-8")

        original_proof_no_val = [{"H": p["H"]} for p in proofs_lst]
        serialized_original_proof = json.dumps(original_proof_no_val).encode("utf-8")

        serialized_secrets      = json.dumps(secrets).encode("utf-8")
        serialized_secrets_aux  = json.dumps(secrets_aux).encode("utf-8")

        # ---- ②  Re‑share with zeros via pyCommitWithZeroFull ----------
        comandproofwithzero = lib.pyCommitWithZeroFull(
            self.srs['Pk'],
            serialized_secrets,
            serialized_secrets_aux,
            self.t
        )
        deser_comandproofwithzero = json.loads(comandproofwithzero.decode("utf-8"))
        serialized_commitment = json.dumps(
            deser_comandproofwithzero["commitmentList"]
        ).encode("utf-8")
        logging.info("deser_comandproofwithzero: %s", deser_comandproofwithzero)

        # Keep per‑party proof list
        proof_list = deser_comandproofwithzero["proofList"]

        # ---- ③  Aggregate proofs at x=0 and per node ------------------
        proof_at_zero_Honly = [{"H": p["H"]} for p in deser_comandproofwithzero.get("proofAtZero", [])]
        serialized_proofAtZero = json.dumps(proof_at_zero_Honly).encode("utf-8")
        challenge = lib.pyDeriveChallenge(serialized_commitment)
        aggproofAtZero = lib.pyAggProveEvalZero(serialized_proofAtZero, challenge)
        ser_aggproofAtZero = json.dumps(json.loads(aggproofAtZero.decode("utf-8"))["aggH"])

        aggregated_proofList = []
        for node_idx in range(self.n):
            node_H_only = [{"H": p["H"]} for p in proof_list[node_idx]]
            agg_node = lib.pyAggProveEvalZero(
                json.dumps(node_H_only).encode("utf-8"),
                challenge
            )
            aggregated_proofList.append(
                json.dumps(json.loads(agg_node.decode("utf-8"))["aggH"])
            )

        
        from Crypto.Util.number import long_to_bytes
        import random

        pk_dict = json.loads(self.srs["Pk"].decode("utf-8"))
        gx_dec = int(pk_dict["G1_g"][0]["X"])
        gy_dec = int(pk_dict["G1_g"][0]["Y"])
        hx_dec = int(pk_dict["G1_h"][0]["X"])
        hy_dec = int(pk_dict["G1_h"][0]["Y"])
        uncompressed_g_hex = (b"\x04" + long_to_bytes(gx_dec,48) + long_to_bytes(gy_dec,48)).hex()
        uncompressed_h_hex = (b"\x04" + long_to_bytes(hx_dec,48) + long_to_bytes(hy_dec,48)).hex()

        # ---- ③.b  Aggregate secrets into a single commitment ----
        # Convert decimal secret values to hex strings for commitment
        secrets_hex = [hex(int(s))[2:] for s in secrets]
        secrets_aux_hex = [hex(int(s))[2:] for s in secrets_aux]
        # Build payload for secrets commitment
        payload_secrets = {
            "g": uncompressed_g_hex,
            "h": uncompressed_h_hex,
            "m": secrets_hex,
            "m_prime": secrets_aux_hex
        }
        # Debug: log the exact JSON sent to pyComputeCommitmentGH
        serialized_payload_secrets = json.dumps(payload_secrets)
        ptr_secrets_commit = lib_bulletproof.pyComputeCommitmentGH(
            serialized_payload_secrets.encode("utf-8")
        )
        secrets_W_list = json.loads(string_at(ptr_secrets_commit).decode("utf-8"))
        lib_bulletproof.pyFreeString(ptr_secrets_commit)
        # Wrap points and serialize
        def _parse_uncompressed_G1(hex_str: str) -> dict:
            data = bytes.fromhex(hex_str)
            if data[0] != 0x04:
                raise ValueError("Invalid uncompressed G1 prefix")
            x = int.from_bytes(data[1:49], byteorder="big")
            y = int.from_bytes(data[49:97], byteorder="big")
            return {"X": str(x), "Y": str(y)}
        secrets_structured = []
        for pt in secrets_W_list:                    # each pt is "(x_hex,y_hex)"
            x_hex, y_hex = pt.strip("()").split(",")
            uncompressed_hex = (b"\x04" +
                                 long_to_bytes(int(x_hex, 16), 48) +
                                 long_to_bytes(int(y_hex, 16), 48)).hex()
            secrets_structured.append({"H": _parse_uncompressed_G1(uncompressed_hex)})
        ser_secrets_structured = json.dumps(secrets_structured).encode("utf-8")
        # Aggregate with challenge
        ptr_secrets_agg = lib.pyAggProveEvalZero(ser_secrets_structured, challenge)
        ser_agg_secrets = json.dumps(json.loads(string_at(ptr_secrets_agg).decode("utf-8"))["aggH"])
        # logging.info("ser_agg_secrets (aggregated secrets): %s", ser_agg_secrets)



        # ---- ④  Encrypt shares & build enc_results --------------------
        #  (reuse earlier code that builds uncompressed_g/h etc.)
        public_keys_list = json.loads(self.public_keys.decode("utf-8"))
        enc_results = []
        # logging.info("public_keys_list: %s", public_keys_list)
        for node_idx, pk_entry in enumerate(public_keys_list):
            if isinstance(pk_entry, dict):
                pk_hex = (b"\x04" + long_to_bytes(int(pk_entry["X"]),48) + long_to_bytes(int(pk_entry["Y"]),48)).hex()
                # logging.info("pk_entry: %s", pk_entry)
            else:
                pk_hex = pk_entry

            r_hex = hex(random.getrandbits(256))[2:]
            k_hex = hex(random.getrandbits(256))[2:]
            # logging.info("node_idx: %d, pk_hex: %s, r_hex: %s, k_hex: %s", node_idx, pk_hex, r_hex, k_hex)

            # ElGamal encrypt g^k
            elg_payload = {
                "g":  uncompressed_g_hex,
                "pk": pk_hex,
                "r":  r_hex,
                "k":  k_hex
            }
            ptr_elg = lib_bulletproof.pyElGamalEncrypt(json.dumps(elg_payload).encode("utf-8"))
            elg_out = json.loads(string_at(ptr_elg).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_elg)
            C1_hex, C2_hex = elg_out["C1"], elg_out["C2"]
            # logging.info("C1_hex: %s, C2_hex: %s", C1_hex, C2_hex)

            # # ---- Compute g^k via GH commitment (m = k_hex, m_prime = 0) ----
            # payload_k = {
            #     "g": uncompressed_g_hex,
            #     "h": uncompressed_h_hex,
            #     "m": [k_hex],
            #     "m_prime": ["0"]
            # }
            # ptr_k = lib_bulletproof.pyComputeCommitmentGH(json.dumps(payload_k).encode("utf-8"))
            # result_k = json.loads(string_at(ptr_k).decode("utf-8"))
            # lib_bulletproof.pyFreeString(ptr_k)
            # logging.info("node_idx: %d, g^k computed via GH: %s", node_idx, result_k)


            # Uncompress C1, C2 from "(x,y)" to uncompressed hex
            c1_x_str, c1_y_str = C1_hex.strip("()").split(",")
            c2_x_str, c2_y_str = C2_hex.strip("()").split(",")
            c1_x_bytes = long_to_bytes(int(c1_x_str, 16), 48)
            c1_y_bytes = long_to_bytes(int(c1_y_str, 16), 48)
            c2_x_bytes = long_to_bytes(int(c2_x_str, 16), 48)
            c2_y_bytes = long_to_bytes(int(c2_y_str, 16), 48)
            c1_hex = (b"\x04" + c1_x_bytes + c1_y_bytes).hex()
            c2_hex = (b"\x04" + c2_x_bytes + c2_y_bytes).hex()
            # logging.info("C1 uncompressed hex: %s", c1_hex)
            # logging.info("C2 uncompressed hex: %s", c2_hex)

            # Extract node‑specific (m,m′) from proof_list
            node_proofs_full = proof_list[node_idx]
            m_list_node  = [hex(int(p["ClaimedValue"]))[2:]    for p in node_proofs_full]
            mp_list_node = [hex(int(p["ClaimedValueAux"]))[2:] for p in node_proofs_full]
            # logging.info("m_list_node: %s", m_list_node)
            # logging.info("mp_list_node: %s", mp_list_node)

            # W commitments
            payload_W = {
                "g": uncompressed_g_hex,
                "h": uncompressed_h_hex,
                "m": m_list_node,
                "m_prime": mp_list_node
            }
            ptr_W = lib_bulletproof.pyComputeCommitmentGH(json.dumps(payload_W).encode("utf-8"))
            result_W = json.loads(string_at(ptr_W).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_W)
            W_list_node = []
            for pt in result_W:
                x_hex, y_hex = pt.strip("()").split(",")
                W_list_node.append((b"\x04" + long_to_bytes(int(x_hex, 16), 48) + long_to_bytes(int(y_hex, 16), 48)).hex())
            # logging.info("W_list_node: %s", W_list_node)

            # # --- Convert uncompressed hex W_list_node to structured JSON points ---
            # def _parse_uncompressed_G1(hex_str: str) -> dict:
            #     data = bytes.fromhex(hex_str)
            #     if data[0] != 0x04:
            #         raise ValueError("Invalid uncompressed G1 prefix")
            #     x = int.from_bytes(data[1:49], byteorder="big")
            #     y = int.from_bytes(data[49:97], byteorder="big")
            #     return {"X": str(x), "Y": str(y)}

            # structured_W_list = [{"H": _parse_uncompressed_G1(w)} for w in W_list_node]
            # # logging.info("structured_W_list (H-wrapped): %s", structured_W_list)
            # # Prepare JSON for pyAggProveEvalZero call (list of {'H': {...}})
            # serialized_structured_W = json.dumps(structured_W_list).encode("utf-8")

            # # --- Use serialized_structured_W and challenge to aggregate W via KZG ---
            # agg_node_W_ptr = lib.pyAggProveEvalZero(serialized_structured_W, challenge)
            # ser_agg_node_W = json.dumps(json.loads(string_at(agg_node_W_ptr).decode("utf-8"))["aggH"])
            # # logging.info("ser_agg_node_W: %s", ser_agg_node_W)

            # # ----- 下面是 pyPubAggVerifyEvalCombined 的验证测试 -----
            # # 验证合并后的 secrets commitment 与 aggproofAtZero
            # try:
            #     ok_combined = lib.pyPubAggVerifyEvalCombined(
            #         self.srs["Vk"],
            #         serialized_commitment,
            #         ser_agg_secrets.encode("utf-8"),
            #         ser_aggproofAtZero.encode("utf-8"),
            #         challenge,
            #         0
            #     )
            #     logging.info("challenge: %s", challenge)
            #     logging.info("[PV-VERIFY-COMBINED] pyPubAggVerifyEvalCombined result: %s", ok_combined)
            # except Exception as e:
            #     logging.error("[PV-VERIFY-COMBINED] error invoking combined verify: %s", e)

            # Bulletproof full proof
            payload_proof = {
                "g":  uncompressed_g_hex,
                "h":  uncompressed_h_hex,
                "pk": pk_hex,
                "C1": c1_hex,
                "C2": c2_hex,
                "r":  r_hex,
                "r_prime": k_hex,
                "m":  m_list_node,
                "m_prime": mp_list_node,
                "W":  W_list_node
            }
            ptr_proof = lib_bulletproof.pyProveFull(json.dumps(payload_proof).encode("utf-8"))
            proof_hex = json.loads(string_at(ptr_proof).decode("utf-8"))["proof"]
            lib_bulletproof.pyFreeString(ptr_proof)

            
            # # --- 验证刚生成的 Bulletproof Full proof ---
            # payload_verify = {
            #     "g":  uncompressed_g_hex,
            #     "h":  uncompressed_h_hex,
            #     "pk": pk_hex,
            #     "C1": c1_hex,
            #     "C2": c2_hex,
            #     "W":  W_list_node,
            #     "proof": proof_hex
            # }
            # json_input_verify = json.dumps(payload_verify).encode("utf-8")
            # ptr_verify = lib_bulletproof.pyVerifyFull(json_input_verify)
            # verify_raw = string_at(ptr_verify).decode("utf-8")
            # lib_bulletproof.pyFreeString(ptr_verify)
            # logging.info("id %d [PV-VERIFY] proof verification result: %s", node_idx, verify_raw)
            # logging.info("id %d [PV-VERIFY] uncompressed_g_hex: %s", node_idx, uncompressed_g_hex)
            # logging.info("id %d [PV-VERIFY] uncompressed_h_hex: %s", node_idx, uncompressed_h_hex)
            # logging.info("id %d [PV-VERIFY] pk_hex: %s", node_idx, pk_hex)
            # logging.info("id %d [PV-VERIFY] C1_hex: %s", node_idx, c1_hex)
            # logging.info("id %d [PV-VERIFY] C2_hex: %s", node_idx, c2_hex)
            # logging.info("id %d [PV-VERIFY] W_list_node: %s", node_idx, W_list_node)
            # logging.info("id %d [PV-VERIFY] proof_hex: %s", node_idx, proof_hex)

            # collect cipher shares (Poseidon sym‑enc)
            cipher_shares = []
            for m_hex, mp_hex in zip(m_list_node, mp_list_node):
                sym_payload = {"pk": pk_hex,"k":k_hex,"m":m_hex,"m_prime":mp_hex}
                ptr_sym = lib_bulletproof.pySymEncrypt(json.dumps(sym_payload).encode("utf-8"))
                sym_out = json.loads(string_at(ptr_sym).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_sym)
                cipher_shares.append((sym_out["c"], sym_out["c_prime"]))
                # logging.info("id %d [PV-TRANSFER] m_hex: %s", node_idx, m_hex)
                # logging.info("id %d [PV-TRANSFER] mp_hex: %s", node_idx, mp_hex)
                # logging.info("id %d [PV-TRANSFER] cipher_shares: %s", node_idx, cipher_shares)

            enc_results.append({
                "node_id": node_idx,
                "pk": pk_hex, 
                "C1": c1_hex,
                "C2": c2_hex,
                "cipher_shares": cipher_shares,
                "W": W_list_node,
                "proof": proof_hex
            })

            # # ---------------- 这里是解密的测试 ----------------
            # # ---------------- Quick ElGamal decrypt self‑test ----------------
            # if node_idx == self.my_id and hasattr(self, "sk_hex_map"):
            #     try:
            #         test_dec_payload = {
            #             "C1": c1_hex,
            #             "C2": c2_hex,
            #             "sk": self.sk_hex_map[self.my_id]
            #         }
            #         ptr_dec_test = lib_bulletproof.pyElGamalDecrypt(
            #             json.dumps(test_dec_payload).encode("utf-8")
            #         )
            #         dec_out = json.loads(string_at(ptr_dec_test).decode("utf-8"))
            #         lib_bulletproof.pyFreeString(ptr_dec_test)
            #         logging.info("[SELF‑TEST] ElGamal quick decrypt OK – msg: %s", dec_out.get("message"))
            #     except Exception as e:
            #         logging.error("[SELF‑TEST] ElGamal quick decrypt failed: %s", e)
            # -----------------------------------------------------------------
        # logging.info("enc_results: %s", enc_results)

        # ---- ⑤  Build dataclass + bytes ------------------------------------
        pv_obj = PVTransferPayload(
            dealer_id              = self.my_id,
            enc_results=[EncResult(**er) for er in enc_results],
            commitment=json.dumps(serialized_commitment.decode("utf-8")),
            agg_proof_at_zero=ser_aggproofAtZero,
            aggregated_proof_list=aggregated_proofList,
            agg_secrets_commitment=ser_agg_secrets,
        )
        
        self.pvtransfer_bytes = pv_obj.to_bytes()
    def __enter__(self):
        return self    
        
    def kill(self):
        try:
            self.subscribe_recv_task.cancel()
            for task in self.acss_tasks:
                task.cancel()
            self.acss.kill()
            self.acss_task.cancel()
        except Exception:
            logging.info("Beaver task finished")
        

    def __exit__(self, type, value, traceback):
        return self

    async def run_pvtransfer(self, node_communicator):
        start_time = time.time()

        logger.info(f"[{self.my_id}] Starting DynamicPVTransfer")        
        serialized_initial_comandproofs = json.dumps(self.initial_comandproofs).encode('utf-8')

        tob = YosoTOB(
            self.public_keys, self.private_key, self.pkbls, self.skbls,
            self.n, self.t, self.srs, self.my_id,
            self.send, self.recv,
            shared_subscribe=(self.subscribe_recv_task, self.subscribe_recv)
        )
        await tob.start()          # 挂后台

        # --- Derive sk_hex map (dealer_id → hex scalar) from the multi‑party private_key blob ---
        try:
            # ① bytes → str
            pk_str = self.private_key.decode() if isinstance(self.private_key, (bytes, bytearray)) else str(self.private_key)

            # ② 一层或两层 json.loads
            first    = json.loads(pk_str)
            key_dict = json.loads(first) if isinstance(first, str) else first

            self.sk_hex_map = {}
            for id_str, b64_sk in key_dict.items():
                dec_bytes = base64.b64decode(b64_sk)          # b"\"4243...\""
                dec_str   = dec_bytes.decode("utf-8").strip('"')  # "4243..."
                sk_int    = int(dec_str)                      # 成为真正大整数
                raw_48    = sk_int.to_bytes(48, "big")        # ⇢ 48 bytes
                self.sk_hex_map[int(id_str)] = raw_48.hex()   # 96-char hex

        except Exception as e:
            logging.error("[PVTRANSFER] failed to build sk_hex_map: %s", e)
            raise
        else:
            logging.info("sk_hex_map: %s", self.sk_hex_map)

        # ——业务进程——
        prepare_start = time.time()
        self._prepare_pvtransfer(serialized_initial_comandproofs)
        prepare_end = time.time()
        logging.info(f"[PVTRANSFER] prepare_pvtransfer took {prepare_end - prepare_start:.3f} seconds")
        # # --- ① 单条触发的等待谓词 ------------------------------------
        # def W_single(L, P):                  # noqa: E306
        #     return len(P) >= 1
        # W_single.min_size = 1
        # tob.set_wait_predicate(W_single)

        # --- ② 广播 & 等待 Deliver -----------------------------------
        tob_broadcast_start = time.time()
        await tob.broadcast(self.pvtransfer_bytes)
        # —— ③ 等待至少一个区块写入 L_P 并获取内容 ——
        height, block_messages = await tob.wait()            # 返回 (height, List[bytes])
        logging.info(f"[PVTRANSFER] Delivered block height={height}, msg count={len(block_messages)}")
        tob_broadcast_end = time.time()
        logging.info(f"[PVTRANSFER] tob.broadcast + wait took {tob_broadcast_end - tob_broadcast_start:.3f} seconds")

        # —— 额外：也可直接通过 get_last_block() 获取最新区块 —— 
        last_block = tob.get_last_block() or []
        logging.info(f"[PVTRANSFER] get_last_block returned {len(last_block)} messages")

        # —— 解析并输出每条 PVTransferPayload —— 
        # —— 初始化存储本节点收到的（dealer_id, C1, C2, cipher_shares） ——
        self.received_entries = []      # List[Dict[str, Any]]

        # —— 解析区块内所有消息，提取本节点相关密文 ——
        decode_start = time.time()
        for idx, raw_entry in enumerate(last_block):
            try:
                pv_obj = PVTransferPayload.from_bytes(raw_entry)
                dealer_id = pv_obj.dealer_id
                for enc in pv_obj.enc_results:
                    if enc.node_id == self.my_id:
                        # 双重 JSON 解码：先解析外层，再解析内层
                        raw_commit = pv_obj.commitment
                        try:
                            first = json.loads(raw_commit)
                            commit_list = json.loads(first) if isinstance(first, str) else first
                        except Exception:
                            commit_list = raw_commit
                        self.received_entries.append({
                            "dealer_id": dealer_id,
                            "C1":  enc.C1,
                            "C2":  enc.C2,
                            "cipher_shares": enc.cipher_shares,
                            "commitment": commit_list
                        })
                        break  # 对该 entry 已找到本节点密文，继续下一条
            except Exception as e:
                logging.error("[PVTRANSFER] failed to parse block entry %d: %s", idx, e)

        # —— ElGamal 解密 —— 
        for i, entry in enumerate(self.received_entries):
            dealer_id = entry["dealer_id"]
            logging.info("[PVTRANSFER] processing entry %d (dealer %d)", i, dealer_id)
            sk_hex    = self.sk_hex_map.get(dealer_id)
            if sk_hex is None:
                logging.error("[PVTRANSFER] no sk for dealer %d (entry %d)", dealer_id, i)
                continue

            payload_dec = {
                "C1": entry["C1"],
                "C2": entry["C2"],
                "sk": sk_hex
            }
            ptr_dec = lib_bulletproof.pyElGamalDecrypt(json.dumps(payload_dec).encode("utf-8"))
            result_dec = json.loads(string_at(ptr_dec).decode("utf-8"))
            lib_bulletproof.pyFreeString(ptr_dec)
            logging.info("[PVTRANSFER] entry %d (dealer %d) ElGamal decrypted: %s",
                         i, dealer_id, result_dec)
            # ---- Convert "(x_hex,y_hex)" → uncompressed G1 hex ----
            msg_str = result_dec.get("message", "").strip("()")
            try:
                x_hex, y_hex = msg_str.split(",")
                gk_bytes = b"\x04" + long_to_bytes(int(x_hex, 16), 48) + long_to_bytes(int(y_hex, 16), 48)
                gk_hex = gk_bytes.hex()
            except Exception as e:
                logging.error("[PVTRANSFER] failed to parse g^k point: %s (raw: %s)", e, msg_str)
                gk_hex = None
            entry["gk"] = gk_hex

        # —— 对称加密(cipher_shares) 解密 —— 
        for i, entry in enumerate(self.received_entries):
            dealer_id = entry["dealer_id"]
            sk_hex = self.sk_hex_map.get(dealer_id)
            if sk_hex is None:
                logging.error("[PVTRANSFER] no sk for dealer %d in symmetric decrypt", dealer_id)
                continue
            gk_hex = entry.get("gk")
            plaintexts = []
            for j, (c_sym, cp_sym) in enumerate(entry.get("cipher_shares", [])):
                payload_sym_dec = {"gk": gk_hex, "sk": sk_hex, "c": c_sym, "c_prime": cp_sym}
                ptr_sym = lib_bulletproof.pySymDecrypt(json.dumps(payload_sym_dec).encode("utf-8"))
                dec_res = json.loads(string_at(ptr_sym).decode("utf-8"))
                lib_bulletproof.pyFreeString(ptr_sym)
                m_hex = dec_res.get("m")
                mp_hex = dec_res.get("m_prime")
                logging.info("[PVTRANSFER] entry %d sym decrypt %d: m=%s, m_prime=%s", i, j, m_hex, mp_hex)
                plaintexts.append((m_hex, mp_hex))
            entry["sym_plaintexts"] = plaintexts

        # —— 对称分享插值 (Lagrange Interpolation) —— 
        # 1. 收集所有 dealer_id 并排序
        common = sorted(entry["dealer_id"] for entry in self.received_entries)
        logging.info("[PVTRANSFER] common: %s", common)
        ser_common = json.dumps(common).encode("utf-8")
        # 2. 构造 shares commitment 和 share 列表
        commits_sel = [
            entry["commitment"]
            for entry in self.received_entries
            if entry["dealer_id"] in common
        ]

        def hex_to_dec(h):
            # 去掉前导 0 再转十进制
            return str(int(h.lstrip("0") or "0", 16))

        shares_sel = [
            [
                {
                    "H": {"X": "1", "Y": "1"},
                    "ClaimedValue":    hex_to_dec(m_hex),
                    "ClaimedValueAux": hex_to_dec(mp_hex)
                }
                for m_hex, mp_hex in entry["sym_plaintexts"]
            ]
            for entry in self.received_entries
            if entry["dealer_id"] in common
        ]
        ser_commit = json.dumps(commits_sel).encode("utf-8")
        ser_share  = json.dumps(shares_sel).encode("utf-8")
        logging.info("[PVTRANSFER] ser_commit: %s", ser_commit.decode("utf-8"))
        logging.info("[PVTRANSFER] ser_share: %s", ser_share.decode("utf-8"))
        # 3. 调用外部 C 接口进行插值
        interpolated_sym = lib.pyInterpolateShareswithTransfer(ser_common, ser_commit, ser_share)
        logging.info("[PVTRANSFER] interpolated symmetric shares: %s", interpolated_sym.decode("utf-8"))

        decode_end = time.time()
        logging.info(f"[PVTRANSFER] decode and interpolation took {decode_end - decode_start:.3f} seconds")

        # --- ③ 优雅关闭 ---------------------------------------------
        await tob.stop()             # 兼容别名 kill()

        logger.info(
            "[%d] PV-Transfer broadcast done – len=%d bytes",
            self.my_id, len(self.pvtransfer_bytes)
        )       

        # The time it takes to write the triples to the file is not included in the total time overhead
        def write_bytes_to_file(file_path, byte_data):
            with open(file_path, 'wb') as file:
                file.write(byte_data)

        write_bytes_to_file(f'transfer/{self.my_id}_transfer.txt', interpolated_sym)

        transfer_time = time.time() - start_time
        
        logger.info(f"[{self.my_id}] [asynchronous dynamic transfer] Finished! Node {self.my_id}, total number: {int ((self.t + 1) * self.batchsize / 2) }, time: {transfer_time} (seconds)")

        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")
        while True:
            await asyncio.sleep(2)
