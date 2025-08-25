import json, base64, ctypes, os
from ctypes import c_int, c_char_p, CDLL
import argparse

import logging

logging.basicConfig(
    filename="setup_transfer.log",
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

parser = argparse.ArgumentParser(description="Offline setup for dynamic transfer")
parser.add_argument("--N", type=int, default=4, help="committee size (number of nodes)")
parser.add_argument("--k", type=int, default=8, help="batch size B")
# parser.add_argument("--t", type=int, default=1, help="threshold t")
args = parser.parse_args()

B = args.k           # batch size
n = args.N           # number of nodes
# Compute integer threshold t = floor((n-1)/3)
t = (n - 1) // 3


lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype  = c_char_p
lib.pyCommit.argtypes  = [c_char_p, c_char_p, c_int]   # (Pk, values, t)
lib.pyCommit.restype   = c_char_p
# Hard-coded SRS public key (Base64-encoded)
# serialized_srs = base64.b64decode(
#     "eyJQayI6eyJHMV9nIjpbeyJYIjoiMzY4NTQxNjc1MzcxMzM4NzAxNjc4MTA4ODMxNTE4MzA3Nzc1Nzk2MTYyMDc5NTc4MjU0NjQwOTg5NDU3ODM3ODY4ODYwNzU5MjM3ODM3NjMxODgzNjA1NDk0NzY3NjM0NTgyMTU0ODEwNDE4NTQ2NDUwNyIsIlkiOiIxMzM5NTA2NTQ0OTQ0NDc2NDczMDIwNDcxMzc5OTQxOTIxMjIxNTg0OTMzODc1OTM4MzQ5NjIwNDI2NTQzNzM2NDE2NTExNDIzOTU2MzMzNTA2NDcyNzI0NjU1MzUzMzY2NTM0OTkyMzkxNzU2NDQxNTY5In0seyJYIjoiMTk4Mzg3Mzc2NTk3NDM5NDA1MzYzODQ0MjUyMzM3NTA4NzQ3MDMzMTc0ODAwMDczNjM4MzU2NzgwODg1NDU5MDQ0NzY1MjA1NDg1OTkwNzgzMDk4OTI0MzAzMjY2OTAwNzY4MjMwMjgwMDgxMDMxODkyMCIsIlkiOiI4NDI5NDc5MDg5Nzc2ODM1ODI4MDcyOTEzOTU1ODU0MjI5NDAyMDkzNjkwMzA0MzgzNDMwMTU1MTYzNDU3OTkwMzY4OTUxMTQyNjI1NzQzNDI4MzYwNjk5OTg4OTI4MDY0MjY1MjQ0Nzc4ODk1NzEwNSJ9XSwiRzFfaCI6W3siWCI6IjM2ODU0MTY3NTM3MTMzODcwMTY3ODEwODgzMTUxODMwNzc3NTc5NjE2MjA3OTU3ODI1NDY0MDk4OTQ1NzgzNzg2ODg2MDc1OTIzNzgzNzYzMTg4MzYwNTQ5NDc2NzYzNDU4MjE1NDgxMDQxODU0NjQ1MDciLCJZIjoiMTMzOTUwNjU0NDk0NDQ3NjQ3MzAyMDQ3MTM3OTk0MTkyMTIyMTU4NDkzMzg3NTkzODM0OTYyMDQyNjU0MzczNjQxNjUxMTQyMzk1NjMzMzUwNjQ3MjcyNDY1NTM1MzM2NjUzNDk5MjM5MTc1NjQ0MTU2OSJ9LHsiWCI6IjE5ODM4NzM3NjU5NzQzOTQwNTM2Mzg0NDI1MjMzNzUwODc0NzAzMzE3NDgwMDA3MzYzODM1Njc4MDg4NTQ1OTA0NDc2NTIwNTQ4NTk5MDc4MzA5ODkyNDMwMzI2NjkwMDc2ODIzMDI4MDA4MTAzMTg5MjAiLCJZIjoiODQyOTQ3OTA4OTc3NjgzNTgyODA3MjkxMzk1NTg1NDIyOTQwMjA5MzY5MDMwNDM4MzQzMDE1NTE2MzQ1Nzk5MDM2ODk1MTE0MjYyNTc0MzQyODM2MDY5OTk4ODkyODA2NDI2NTI0NDc3ODg5NTcxMDUifV19LCJWayI6eyJHMiI6W3siWCI6eyJBMCI6IjM1MjcwMTA2OTU4NzQ2NjYxODE4NzEzOTExNjAxMTA2MDE0NDg5MDAyOTk1Mjc5Mjc3NTI0MDIxOTkwODY0NDIzOTc5Mzc4NTczNTcxNTAyNjg3MzM0NzYwMDM0Mzg2NTE3NTk1Mjc2MTkyNjMwMzE2MCIsIkExIjoiMzA1OTE0NDM0NDI0NDIxMzcwOTk3MTI1OTgxNDc1Mzc4MTYzNjk4NjQ3MDMyNTQ3NjY0NzU1ODY1OTM3MzIwNjI5MTYzNTMyNDc2ODk1ODQzMjQzMzUwOTU2MzEwNDM0NzAxNzgzNzg4NTc2MzM2NTc1OCJ9LCJZIjp7IkEwIjoiMTk4NTE1MDYwMjI4NzI5MTkzNTU2ODA1NDUyMTE3NzE3MTYzODMwMDg2ODk3ODIxNTY1NTczMDg1OTM3ODY2NTA2NjM0NDcyNjM3MzgyMzcxODQyMzg2OTEwNDI2MzMzMzk4NDY0MTQ5NDM0MDM0NzkwNSIsIkExIjoiOTI3NTUzNjY1NDkyMzMyNDU1NzQ3MjAxOTY1Nzc2MDM3ODgwNzU3NzQwMTkzNDUzNTkyOTcwMDI1MDI3OTc4NzkzOTc2ODc3MDAyNjc1NTY0OTgwOTQ5Mjg5NzI3OTU3NTY1NTc1NDMzMzQ0MjE5NTgyIn19LHsiWCI6eyJBMCI6IjM4NjQxOTE5ODQ3ODk3ODI0NTA2ODY4MTcwMDE1NjYwOTA5MDQ2NjUwMzk0NTA2OTIwMDQ5Mjg4Mzc4NDk4MjA2MzUxMzI0MzUwMjYzMzUwNzU1MDg3NzQwNzcxMDY4MTEyNjQ2NDQzNTIxODI4NjI5MTYiLCJBMSI6IjE5MjM3MTUyODM2MjgxMjk1MTc4OTMxMDU4NDI2MTU5NTk4MzAzNjM0OTg3MDI0OTc2NjQ3NDU5NzQ5OTA1ODg5OTYyMDkzMzE4MTM4NDM1ODk2MzI0MTQ4MjQwMDE2MjA5NDQyNjk0NDAwODAzNzk4OTIifSwiWSI6eyJBMCI6IjY5MTIzOTIxMDAwNzQ2ODkwMjI0MTYwNjc0NjY5OTcwNTgzMzA4MjgyNjg4MTA3NzE3NDg3OTY5Mzg0MzU1OTgzOTA5MDU5OTQyNzI5NTQyNDM2MTg0NDI4ODc4ODgxNjgzNTEzNDAxNTgwODYxNTkwMSIsIkExIjoiMjcwNDc4NzQzOTQwMTcyODI0NDExMTc1NTM2NjAwNTA2MTE5MDAyMzU0MDg2NTI3NTg1Mzc3NzIwNzA3NTIyNjE1MzY0MjI0NjczMjUwNDUwODAxNTAyMDEzOTA1ODIyMDk3MTcyNjI2MzQ2Mzg0NTUxMCJ9fV0sIkcxX2ciOnsiWCI6IjM2ODU0MTY3NTM3MTMzODcwMTY3ODEwODgzMTUxODMwNzc3NTc5NjE2MjA3OTU3ODI1NDY0MDk4OTQ1NzgzNzg2ODg2MDc1OTIzNzgzNzYzMTg4MzYwNTQ5NDc2NzYzNDU4MjE1NDgxMDQxODU0NjQ1MDciLCJZIjoiMTMzOTUwNjU0NDk0NDQ3NjQ3MzAyMDQ3MTM3OTk0MTkyMTIyMTU4NDkzMzg3NTkzODM0OTYyMDQyNjU0MzczNjQxNjUxMTQyMzk1NjMzMzUwNjQ3MjcyNDY1NTM1MzM2NjUzNDk5MjM5MTc1NjQ0MTU2OSJ9LCJHMV9oIjp7IlgiOiIzNjg1NDE2NzUzNzEzMzg3MDE2NzgxMDg4MzE1MTgzMDc3NzU3OTYxNjIwNzk1NzgyNTQ2NDA5ODk0NTc4Mzc4Njg4NjA3NTkyMzc4Mzc2MzE4ODM2MDU0OTQ3Njc2MzQ1ODIxNTQ4MTA0MTg1NDY0NTA3IiwiWSI6IjEzMzk1MDY1NDQ5NDQ0NzY0NzMwMjA0NzEzNzk5NDE5MjEyMjE1ODQ5MzM4NzU5MzgzNDk2MjA0MjY1NDM3MzY0MTY1MTE0MjM5NTYzMzM1MDY0NzI3MjQ2NTUzNTMzNjY1MzQ5OTIzOTE3NTY0NDE1NjkifX19"
# )
serialized_srs = base64.b64decode(
    "eyJQayI6eyJHMV9nIjpbeyJYIjoiMzY4NTQxNjc1MzcxMzM4NzAxNjc4MTA4ODMxNTE4MzA3Nzc1Nzk2MTYyMDc5NTc4MjU0NjQwOTg5NDU3ODM3ODY4ODYwNzU5MjM3ODM3NjMxODgzNjA1NDk0NzY3NjM0NTgyMTU0ODEwNDE4NTQ2NDUwNyIsIlkiOiIxMzM5NTA2NTQ0OTQ0NDc2NDczMDIwNDcxMzc5OTQxOTIxMjIxNTg0OTMzODc1OTM4MzQ5NjIwNDI2NTQzNzM2NDE2NTExNDIzOTU2MzMzNTA2NDcyNzI0NjU1MzUzMzY2NTM0OTkyMzkxNzU2NDQxNTY5In0seyJYIjoiMTk4Mzg3Mzc2NTk3NDM5NDA1MzYzODQ0MjUyMzM3NTA4NzQ3MDMzMTc0ODAwMDczNjM4MzU2NzgwODg1NDU5MDQ0NzY1MjA1NDg1OTkwNzgzMDk4OTI0MzAzMjY2OTAwNzY4MjMwMjgwMDgxMDMxODkyMCIsIlkiOiI4NDI5NDc5MDg5Nzc2ODM1ODI4MDcyOTEzOTU1ODU0MjI5NDAyMDkzNjkwMzA0MzgzNDMwMTU1MTYzNDU3OTkwMzY4OTUxMTQyNjI1NzQzNDI4MzYwNjk5OTg4OTI4MDY0MjY1MjQ0Nzc4ODk1NzEwNSJ9XSwiRzFfaCI6W3siWCI6IjM4NzI0NzM2ODkyMDc4OTIzNzg0NzAzMzUzOTUxMTQ5MDI2MzExNzY1NDEwMjg5MTYxNTg2MjYxNjE2NjI4NDA5MzQzMTUyNDE1Mzk0MzkxNjAzMDE1NjQzNDQ5MDUyNjA2MTI2NDI3ODM2NDQwMjM5OTEiLCJZIjoiMjU0NzgwNjM5MDQ3NDg0NjM3ODQ5MTE0NTEyNzUxNTQyNzQ1MTI3OTQzMDg4OTEwMTI3NzE2OTg5MDMzNDczNzQwNjE4MDI3Nzc5MjE3MTA5MjE5NzgyNDI1MTYzMjYzMTY3MTYwOTg2MDUwNTk5OTkwMCJ9LHsiWCI6IjUzOTg5NjAyMzExOTE1NjcyMzMxODczOTQ0Nzc1Mjk5NDE1OTEwNDM2Nzg1ODA3NjAwMjYwMjc5MjI5Mjk2OTExMzU0NjYzMTMyODQ1MDI3NDAxMTEyNTY1ODkyMzg2MjE3NDg4MjY3OTg1NTE4MjI2OCIsIlkiOiIxNTkzMjMyMDM3NDIyNzA0NzgwNjA4MzkyMzk3MjEyNjI2NDI4ODcwNzY1MTI1MzA3NTMzNTE1NjY1MDExNzU1MjE1NzA5OTU5NDc3NjkzNTcxODQ5NTg3ODczNDYxNzk4ODQ1MTI2NjUyNzE2MzQ2OTcxIn1dfSwiVmsiOnsiRzIiOlt7IlgiOnsiQTAiOiIzNTI3MDEwNjk1ODc0NjY2MTgxODcxMzkxMTYwMTEwNjAxNDQ4OTAwMjk5NTI3OTI3NzUyNDAyMTk5MDg2NDQyMzk3OTM3ODU3MzU3MTUwMjY4NzMzNDc2MDAzNDM4NjUxNzU5NTI3NjE5MjYzMDMxNjAiLCJBMSI6IjMwNTkxNDQzNDQyNDQyMTM3MDk5NzEyNTk4MTQ3NTM3ODE2MzY5ODY0NzAzMjU0NzY2NDc1NTg2NTkzNzMyMDYyOTE2MzUzMjQ3Njg5NTg0MzI0MzM1MDk1NjMxMDQzNDcwMTc4Mzc4ODU3NjMzNjU3NTgifSwiWSI6eyJBMCI6IjE5ODUxNTA2MDIyODcyOTE5MzU1NjgwNTQ1MjExNzcxNzE2MzgzMDA4Njg5NzgyMTU2NTU3MzA4NTkzNzg2NjUwNjYzNDQ3MjYzNzM4MjM3MTg0MjM4NjkxMDQyNjMzMzM5ODQ2NDE0OTQzNDAzNDc5MDUiLCJBMSI6IjkyNzU1MzY2NTQ5MjMzMjQ1NTc0NzIwMTk2NTc3NjAzNzg4MDc1Nzc0MDE5MzQ1MzU5Mjk3MDAyNTAyNzk3ODc5Mzk3Njg3NzAwMjY3NTU2NDk4MDk0OTI4OTcyNzk1NzU2NTU3NTQzMzM0NDIxOTU4MiJ9fSx7IlgiOnsiQTAiOiIzODY0MTkxOTg0Nzg5NzgyNDUwNjg2ODE3MDAxNTY2MDkwOTA0NjY1MDM5NDUwNjkyMDA0OTI4ODM3ODQ5ODIwNjM1MTMyNDM1MDI2MzM1MDc1NTA4Nzc0MDc3MTA2ODExMjY0NjQ0MzUyMTgyODYyOTE2IiwiQTEiOiIxOTIzNzE1MjgzNjI4MTI5NTE3ODkzMTA1ODQyNjE1OTU5ODMwMzYzNDk4NzAyNDk3NjY0NzQ1OTc0OTkwNTg4OTk2MjA5MzMxODEzODQzNTg5NjMyNDE0ODI0MDAxNjIwOTQ0MjY5NDQwMDgwMzc5ODkyIn0sIlkiOnsiQTAiOiI2OTEyMzkyMTAwMDc0Njg5MDIyNDE2MDY3NDY2OTk3MDU4MzMwODI4MjY4ODEwNzcxNzQ4Nzk2OTM4NDM1NTk4MzkwOTA1OTk0MjcyOTU0MjQzNjE4NDQyODg3ODg4MTY4MzUxMzQwMTU4MDg2MTU5MDEiLCJBMSI6IjI3MDQ3ODc0Mzk0MDE3MjgyNDQxMTE3NTUzNjYwMDUwNjExOTAwMjM1NDA4NjUyNzU4NTM3NzcyMDcwNzUyMjYxNTM2NDIyNDY3MzI1MDQ1MDgwMTUwMjAxMzkwNTgyMjA5NzE3MjYyNjM0NjM4NDU1MTAifX1dLCJHMV9nIjp7IlgiOiIzNjg1NDE2NzUzNzEzMzg3MDE2NzgxMDg4MzE1MTgzMDc3NzU3OTYxNjIwNzk1NzgyNTQ2NDA5ODk0NTc4Mzc4Njg4NjA3NTkyMzc4Mzc2MzE4ODM2MDU0OTQ3Njc2MzQ1ODIxNTQ4MTA0MTg1NDY0NTA3IiwiWSI6IjEzMzk1MDY1NDQ5NDQ0NzY0NzMwMjA0NzEzNzk5NDE5MjEyMjE1ODQ5MzM4NzU5MzgzNDk2MjA0MjY1NDM3MzY0MTY1MTE0MjM5NTYzMzM1MDY0NzI3MjQ2NTUzNTMzNjY1MzQ5OTIzOTE3NTY0NDE1NjkifSwiRzFfaCI6eyJYIjoiMzg3MjQ3MzY4OTIwNzg5MjM3ODQ3MDMzNTM5NTExNDkwMjYzMTE3NjU0MTAyODkxNjE1ODYyNjE2MTY2Mjg0MDkzNDMxNTI0MTUzOTQzOTE2MDMwMTU2NDM0NDkwNTI2MDYxMjY0Mjc4MzY0NDAyMzk5MSIsIlkiOiIyNTQ3ODA2MzkwNDc0ODQ2Mzc4NDkxMTQ1MTI3NTE1NDI3NDUxMjc5NDMwODg5MTAxMjc3MTY5ODkwMzM0NzM3NDA2MTgwMjc3NzkyMTcxMDkyMTk3ODI0MjUxNjMyNjMxNjcxNjA5ODYwNTA1OTk5OTAwIn19fQ=="
)


srs_debug_str = serialized_srs.decode('utf-8')
deserialized_srs_kzg = json.loads(srs_debug_str)
# --- debug: check whether the first generators are identical ---
pk_dict = deserialized_srs_kzg["Pk"]
g0 = pk_dict["G1_g"][0]          # generator for main poly
h0 = pk_dict["G1_h"][0]          # generator for aux  poly
equal = g0 == h0

logging.info("g[0] == h[0] ? %s", equal)
print("DEBUG  g[0] == h[0] ? ", equal)
# ---------------------------------------------------------------
srs = {}
srs['Pk'] = json.dumps(deserialized_srs_kzg['Pk']).encode('utf-8')
srs['Vk'] = json.dumps(deserialized_srs_kzg['Vk']).encode('utf-8')

logging.info("Vk keys: %s", list(deserialized_srs_kzg["Vk"].keys()))

secrets_json = lib.pySampleSecret(B)    # bytes: ["...",...]
commit_json  = lib.pyCommit(srs['Pk'], secrets_json, t)  # bytes

evaluationproofs = []  # proofs for polynomial evaluation (H only)
shares = []
com_and_proofs = json.loads(commit_json.decode('utf-8'))

# logging.info("com_and_proofs: %s", com_and_proofs)

# 拆分 commitment 和每个节点对应的 proof（含 share + evaluation proof）并写入
os.makedirs("init_inputs", exist_ok=True)

# 获取 commitment（所有节点共享）
commitments = com_and_proofs.get("commitmentList", [])
# 重命名为统一格式
com_and_proofs["commitment"] = commitments

# 拆分 proof
all_node_proofs = com_and_proofs.get("batchproofsofallparties", [])

for i in range(n):
    node_proof = all_node_proofs[i]
    com_and_proof_obj = {
        "commitment": commitments,
        "proof": node_proof  # proof 中每一项含 H、ClaimedValue 和 ClaimedValueAux
    }
    logging.info("com_and_proof_obj: %s", com_and_proof_obj)
    with open(f"init_inputs/node{i}.json", "w") as fout:
        json.dump(com_and_proof_obj, fout, indent=2)

# # Normalize keys to match expected format: 'commitment' and flat 'proof' list
# # Rename 'commitmentList' -> 'commitment'
# normalized_commitment = com_and_proofs.get('commitmentList', [])
# # Flatten batchproofsofallparties into a single proof list
# raw_batches = com_and_proofs.get('batchproofsofallparties', [])
# flattened_proof = []
# for batch in raw_batches:
#     flattened_proof.extend(batch)
# # Replace keys in the dict
# com_and_proofs.clear()
# com_and_proofs['commitment'] = normalized_commitment
# com_and_proofs['proof'] = flattened_proof
# logging.info("normalized com_and_proofs: %s", com_and_proofs)

# for i in range(n):
#     node_items = com_and_proofs["batchproofsofallparties"][i]
#     # Each share should include both the value and its auxiliary field
#     node_shares = [
#         {"ClaimedValue": item["ClaimedValue"], "ClaimedValueAux": item["ClaimedValueAux"]}
#         for item in node_items
#     ]
#     # Proofs only keep the group element H
#     node_eval_proofs = [item["H"] for item in node_items]  # one H per share
#     shares.append(json.dumps(node_shares).encode("utf-8"))
#     evaluationproofs.append(json.dumps(node_eval_proofs).encode("utf-8"))


# commitments = com_and_proofs["commitmentList"]   #  C_k^ℓ，batch B

# os.makedirs("init_inputs", exist_ok=True)

# for i in range(n):
#     node_share_obj = json.loads(shares[i].decode("utf-8"))
#     node_eval_proof_obj = json.loads(evaluationproofs[i].decode("utf-8"))

#     with open(f"init_inputs/node{i}.json", "w") as fout:
#         json.dump(
#             {
#                 "batchsize": B,
#                 "commitments": commitments,
#                 "shares":      node_share_obj,
#                 "evaluationproofs": node_eval_proof_obj,
#             },
#             fout,
#             indent=2,
#         )

# logging.info("offline setup done, files written to ./init_inputs/")
