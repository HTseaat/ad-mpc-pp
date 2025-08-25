import json, base64, ctypes, os
from ctypes import c_int, c_char_p, CDLL
import argparse

from binascii import unhexlify
from Crypto.Util.number import long_to_bytes

import logging

logging.basicConfig(
    filename="setup_batch_multiplication.log",
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

parser = argparse.ArgumentParser(description="Offline setup for dynamic transfer")
parser.add_argument("--N", type=int, default=4, help="committee size (number of nodes)")
parser.add_argument("--k", type=int, default=8, help="number of multiplication gates M")
# parser.add_argument("--t", type=int, default=1, help="threshold t")
args = parser.parse_args()

M = args.k           # number of multiplication gates
n = args.N           # number of nodes
# Compute integer threshold t = floor((n-1)/3)
t = (n - 1) // 3


lib = CDLL("./kzg_ped_out.so")
lib.pySampleSecret.argtypes = [c_int]
lib.pySampleSecret.restype  = c_char_p
lib.pyCommit.argtypes  = [c_char_p, c_char_p, c_int]   # (Pk, values, t)
lib.pyCommit.restype   = c_char_p
# Hard-coded SRS public key (Base64-encoded)
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

# logging.info("g[0]: %s", g0)
# logging.info("h[0]: %s", h0)
logging.info("g[0] == h[0] ? %s", equal)
print("DEBUG  g[0] == h[0] ? ", equal)

# ---------------------------------------------------------------
srs = {}
srs['Pk'] = json.dumps(deserialized_srs_kzg['Pk']).encode('utf-8')
srs['Vk'] = json.dumps(deserialized_srs_kzg['Vk']).encode('utf-8')

logging.info("Vk keys: %s", list(deserialized_srs_kzg["Vk"].keys()))

secrets_json = lib.pySampleSecret(2 * M)    # bytes: ["...",...]
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

# Split 2M sharings into left_inputs and right_inputs for each node
for i in range(n):
    node_proof = all_node_proofs[i]
    left_inputs = node_proof[:M]
    right_inputs = node_proof[M:]
    left_commitments = commitments[:M]
    right_commitments = commitments[M:]
    comandproof_left_inputs = {
        "commitment": left_commitments,
        "proof": left_inputs
    }
    comandproof_right_inputs = {
        "commitment": right_commitments,
        "proof": right_inputs
    }
    with open(f"init_inputs/node{i}_left.json", "w") as f_left:
        json.dump(comandproof_left_inputs, f_left, indent=2)
    with open(f"init_inputs/node{i}_right.json", "w") as f_right:
        json.dump(comandproof_right_inputs, f_right, indent=2)
    logging.info("comandproof_left_inputs: %s", comandproof_left_inputs)
    logging.info("comandproof_right_inputs: %s", comandproof_right_inputs)
