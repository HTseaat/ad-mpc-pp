

"""
Minimal YOSO‑style implementation of **Protocol ΠGather** (Fig. 17, KN23).

* Prototype assumptions
    • All M nodes act as every committee C_Gather;r‑1  (no VRF filter yet)
    • Byzantine threshold t satisfies n = 3t + 1
    • “Justifier” checks are stubbed out – always True for now
    • No FCF / coin‑flip messages are required in ΠGather

API
----
Each node runs **one** instance of `YosoGather`:

    g = YosoGather(my_id, n, t, B_i, send, recv)
    await g.run_gather()        # blocks until U₃ is produced
    result = g.U                # dict  {node_id : B_j}

The constructor re‑uses `wrap_send` and `subscribe_recv` helpers from
`beaver.utils.misc`, i.e. the exact same plumbing used by `yosorbc.py`.
"""

from .yosorbc import YosoRBC
import asyncio
import json
import logging
from typing import Dict
from typing import Optional
import base64
from ctypes import *
from Crypto.Util.number import long_to_bytes
import hashlib
import time

from beaver.utils.misc import wrap_send, subscribe_recv

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
#  Hard‑coded VRF demo keys (identical to yosorbc.py)
# ---------------------------------------------------------------------
VRF_SK_LIST_DEC = [
    "39684306934200628374790832935093942049972679047517058306402599924255584325923",
    "14236222537842708546874112184351253866756004511351069863029537419755939864161",
    "42843285076956423279081221618218366758458148780378287252062665261680499789919",
    "10292759882409329422869248954468517761075898603670985626483032301389638736913",
]

VRF_PK_LIST = [
    {"X": "2800536725478797038429894617276931327499960559041671193664286745206032902706469545235682022910870512862229350635684",
     "Y": "2662599614897234480012042624670396418847466353247909535279931623480063060814145614210541637068365508142865030238424"},
    {"X": "2336529599939264010487459386886650974838539949738113810998353069569026160126365555939890093577679930923184835477809",
     "Y": "3896638076421094658326056455325616314073685805704605344222119937768407844818865064740555486604513844697018340417873"},
    {"X": "2787746885153751546777680930011550773315387623395911480525739676754782973542566817566332588651454948148806418198614",
     "Y": "1153657733473902307541504549555561187596772146084780301778042861714142692958393096713346961812902509092994185026213"},
    {"X": "1185050701368738019291486048165328155160983288869986820311853419671144030008553077979444969631331167076881723615686",
     "Y": "2936150378811695273132718299330853003115032863340657961246733482816024136199819911915927265058373251989219060577530"},
]

# ---------------------------------------------------------------------
#  Optional VRF FFI – falls back to stubs if the shared library is absent
# ---------------------------------------------------------------------
try:
    lib_bulletproof = CDLL("./libbulletproofs_amcl.so")
    lib_bulletproof.pyVrfProve.argtypes  = [c_char_p]
    lib_bulletproof.pyVrfProve.restype   = c_void_p
    lib_bulletproof.pyVrfVerify.argtypes = [c_char_p]
    lib_bulletproof.pyVrfVerify.restype  = c_void_p
    lib_bulletproof.pyFreeString.argtypes = [c_void_p]
    lib_bulletproof.pyFreeString.restype  = None
except OSError:
    lib_bulletproof = None

# ---------------------------------------------------------------------
#  Helper hash function
# ---------------------------------------------------------------------
def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ----------------------------------------------------------------------
#  定义一份真正的「区块」数据
#  （只是示例字段，按你协议里的实际元素补全）
# ----------------------------------------------------------------------
from dataclasses import dataclass, asdict
from typing import Dict, List
import json, base64


class YosoGather:
    """
    Three‑round Justified‑Gather (ΠGather) with the *large‑core* guarantee:
        – R₁ collect ≥ n − t  singletons          → U₁
        – R₂ collect ≥ n − t  sets of size ≥ n‑t   → U₂
        – R₃ collect ≥ n − t  sets (again)         → U₃
    For the prototype each round’s “committee” is simply the whole network.
    """

    def __init__(self,
                public_keys, private_key,      # PKI
                pkbls, skbls,                  # BLS
                n, t, srs, my_id,              # Committee Size/Threshold
                send, recv,
                B_i, *, shared_subscribe: Optional[tuple] = None):
        """
        Parameters
        ----------
        my_id : int
            This node’s identifier (0‑based).
        n, t : int
            Committee size and Byzantine threshold (must match n = 3t + 1).
        B_i : bytes
            This node’s *input block* (satisfies J_in by assumption).
        srs : dict
            Structured reference string for VRF.
        private_key : any
            Private key for VRF (not used in stub).
        send, recv : Callable
            Point‑to‑point network primitives identical to those passed to
            `YosoRBC` – see `beaver.utils.misc`.
        """
        assert n >= 3 * t + 1, "need n ≥ 3t + 1"

        self.my_id, self.n, self.t = my_id, n, t
        self.B_i = B_i
        self.send, self.recv = send, recv
        self.srs = srs
        self.public_keys = public_keys
        self.pkbls = pkbls
        self.skbls = skbls
        self.private_key = private_key
        self.vrf_sk_list = VRF_SK_LIST_DEC
        self.vrf_pk_list = VRF_PK_LIST

        # ------------------------------------------------------------------
        # Glue code: subscribe_recv() splits a single receive coroutine
        #            into independent tagged sub‑receivers.  If the caller
        #            already created such a splitter, reuse it to avoid
        #            double‑consuming the same underlying channel.
        # ------------------------------------------------------------------
        if shared_subscribe is not None:
            self._subscribe_task, self._subscribe_recv = shared_subscribe
        else:
            self._subscribe_task, self._subscribe_recv = subscribe_recv(recv)
        def _recv(tag):                 # curry for convenience
            return self._subscribe_recv(tag)
        self._recv = _recv

        # Broadcast helper identical to yosorbc.py
        def _mk_broadcast(tag: str):
            p2p_send = wrap_send(tag, send)        # closure over tag

            async def broadcast(payload: bytes):
                for dest in range(self.n):
                    p2p_send(dest, payload)
            return broadcast
        self._mk_broadcast = _mk_broadcast

        # -------------------------  PGather state  ------------------------
        # U_r  is stored as  Dict[int, bytes]  (node_id → B_j).
        self.U: Dict[int, bytes] = {self.my_id: self.B_i}
        # In ΠGradedGather we also need the intersection T after the extra round
        self.T: Dict[int, bytes] = {}

    # ..............................................................
    #  VRF helpers – identical to yosorbc.py
    # ..............................................................
    def _get_generator_hex(self):
        if hasattr(self, "_cached_g_hex"):
            return self._cached_g_hex
        if self.srs is None:
            return ""      # stub
        pk_dict = json.loads(self.srs["Pk"].decode("utf-8"))
        g0 = pk_dict["G1_g"][0]
        gx = long_to_bytes(int(g0["X"]), 48)
        gy = long_to_bytes(int(g0["Y"]), 48)
        self._cached_g_hex = (b'\x04' + gx + gy).hex()
        return self._cached_g_hex

    def _is_committee_member(self, label: bytes):
        # Prototype: everyone is in the committee; still emit a proof
        if lib_bulletproof is None:
            return True, "{}"

        msg_hex = label.hex()
        sk_int  = int(self.vrf_sk_list[self.my_id])
        sk_hex  = hex(sk_int)[2:]

        payload = {
            "sk":  sk_hex,
            "msg": msg_hex,
            "g":   self._get_generator_hex()
        }
        ptr = lib_bulletproof.pyVrfProve(json.dumps(payload).encode())
        proof = json.loads(string_at(ptr).decode())
        lib_bulletproof.pyFreeString(ptr)
        return True, proof

    def _verify_vrf_proof(self, label: bytes, proof: dict, sender_id: int):
        if lib_bulletproof is None:
            return True
        msg_hex = label.hex()
        pk_entry = self.vrf_pk_list[sender_id]
        gx_bytes = long_to_bytes(int(pk_entry["X"]), 48)
        gy_bytes = long_to_bytes(int(pk_entry["Y"]), 48)
        pk_hex   = (b'\x04' + gx_bytes + gy_bytes).hex()

        # parse beta
        beta_str = proof["beta"].strip("()")
        bx, by = beta_str.split(",")
        beta_hex = (b'\x04' + bytes.fromhex(bx) + bytes.fromhex(by)).hex()

        payload = {
            "pk":   pk_hex,
            "msg":  msg_hex,
            "beta": beta_hex,
            "c":    proof["c"],
            "s":    proof["s"],
            "g":    self._get_generator_hex()
        }
        ptr = lib_bulletproof.pyVrfVerify(json.dumps(payload).encode())
        raw = string_at(ptr).decode()
        lib_bulletproof.pyFreeString(ptr)
        try:
            res = json.loads(raw)
            return bool(res.get("valid", res.get("ok", False)))
        except Exception:
            return raw.strip().lower() in ("true", "1")

    # ----------------------------------------------------------------------
    #  (Stub) Justifier – always returns True for now
    # ----------------------------------------------------------------------
    @staticmethod
    def _justifier(_candidate: Dict[int, bytes]) -> bool:
        return True
    
    # ----------------------------------------------------------------------
    #  One gather round – via concurrent YosoRBC sessions
    # ----------------------------------------------------------------------
    async def _one_round_yosorbc(self, r: int):
        """
        Round *r* 逻辑：
            • 每个 sender_id ∈ {0,…,n-1} 都对应一个独立的 RBC 会话
            prefix = "GATHER_R{r}_{sender_id}"
            • 我们为所有 n 个 prefix 启动 reactor；
            若自己在本轮委员会，就调用对应 prefix 的 sender()
            • 当收集到 ≥ n-t 条 RBC-OUTPUT 后，把它们并集成 U_r
        """
        # 0) 为每个 sender_id 建一个 YosoRBC 实例 + reactor
        rbc_sessions = {}
        reactor_tasks = []
        output_tasks  = {}        # asyncio.Task → sender_id

        for sid in range(self.n):
            prefix = f"GATHER_R{r}_{sid}"
            rbc = YosoRBC(
                self.public_keys, self.private_key,
                self.pkbls, self.skbls,
                self.n, self.t, self.srs, self.my_id,
                self.send, self.recv,
                prefix = prefix, 
                shared_subscribe=(self._subscribe_task, self._subscribe_recv)   # <── 新增
            )
            rbc_sessions[sid] = rbc
            reactor_tasks.append(asyncio.create_task(rbc.reactor()))
            output_tasks[asyncio.create_task(rbc.output_queue.get())] = sid

        # 1) 如果自己在本轮委员会 → 当 sender
        committee_label = f"GATHER_R{r}".encode()
        in_comm, proof_self = self._is_committee_member(committee_label)
        if in_comm:
            payload = json.dumps({
                "from": self.my_id,
                "U": {str(k): v.hex() for k, v in self.U.items()},
                "proof": proof_self
            }).encode()
            await rbc_sessions[self.my_id].sender(payload)
        logger.info("[GATHER] round %d  node %d in committee: %s",
                    r, self.my_id, in_comm)

        # 2) 等待 ≥ n-t 个 RBC-OUTPUT
        collected = {}
        while len(collected) < self.n - self.t:
            collect_time_start = time.time()
            rbc_output_time_start = time.time()
            done, _ = await asyncio.wait(output_tasks.keys(),
                                        return_when=asyncio.FIRST_COMPLETED)
            rbc_output_time_end = time.time()
            logger.info(f"[GATHER] round {r} RBC output wait took {rbc_output_time_end - rbc_output_time_start:.3f} seconds")
            logger.info("[GATHER] round %d  got %d RBC-OUTPUTs, waiting for %d more",
                        r, len(collected), self.n - self.t - len(collected))
            for fut in done:
                sid = output_tasks.pop(fut)
                try:
                    m_bytes, _ = fut.result()
                except asyncio.CancelledError:
                    continue
                msg = json.loads(m_bytes.decode())
                U_j = {int(k): bytes.fromhex(h) for k, h in msg["U"].items()}
                # 2.a  verify VRF proof
                proof_j = msg.get("proof", {})
                if not self._verify_vrf_proof(committee_label, proof_j, sid):
                    logger.warning("[GATHER] round %d  invalid proof from %d – drop", r, sid)
                    continue

                collected[sid] = U_j
                logger.info("[GATHER] round %d got RBC from %d  |U|=%d",
                            r, sid, len(U_j))
            collect_time_end = time.time()
            logger.info(f"[GATHER] round {r} collect step took {collect_time_end - collect_time_start:.3f} seconds")

        # 3) 并集形成 U_r
        new_U = {}
        for U_j in collected.values():
            new_U.update(U_j)
        self.U = new_U
        logger.info("[GATHER] round %d finished – |U_%d|=%d",
                    r, r, len(self.U))

        # 4) 清理剩余异步任务
        for fut in output_tasks: fut.cancel()
        for t in reactor_tasks:  t.cancel()

    # ----------------------------------------------------------------------
    #  Extra round for ΠGradedGather (Fig. 18)
    # ----------------------------------------------------------------------
    async def _graded_gather_yosorbc(self):
        """
        Perform the additional causal‑cast round of ΠGradedGather.

        Steps
        -----
        1. Spawn n concurrent YosoRBC sessions with prefix “GGATHER_<sid>”.
        2. If we are in committee C_GradedGather (prototype: everyone is),
           RBC‑send our local U (obtained after the 3 ΠGather rounds).
        3. Wait until ≥ n−t RBC OUTPUTs are delivered.
        4. Compute
               U =  ⋃  U′_j        (union)
               T =  ⋂  U′_j        (intersection)
           and store them in `self.U` and `self.T`.
        """
        prefix_base = "GGATHER"

        # 0)  spawn all RBC sessions (one per potential sender)
        rbc_sessions, reactor_tasks, output_tasks = {}, [], {}
        for sid in range(self.n):
            rbc = YosoRBC(
                self.public_keys, self.private_key,
                self.pkbls, self.skbls,
                self.n, self.t, self.srs, self.my_id,
                self.send, self.recv,
                prefix=f"{prefix_base}_{sid}",
                shared_subscribe=(self._subscribe_task, self._subscribe_recv)
            )
            rbc_sessions[sid] = rbc
            reactor_tasks.append(asyncio.create_task(rbc.reactor()))
            output_tasks[asyncio.create_task(rbc.output_queue.get())] = sid

        # 1)  committee membership & optional send
        committee_label = prefix_base.encode()
        in_comm, proof_self = self._is_committee_member(committee_label)
        if in_comm:
            payload = json.dumps({
                "from": self.my_id,
                "U": {str(k): v.hex() for k, v in self.U.items()},
                "proof": proof_self
            }).encode()
            await rbc_sessions[self.my_id].sender(payload)
        logger.info("[GGATHER] node %d in committee: %s", self.my_id, in_comm)

        # 2)  collect ≥ n−t RBC OUTPUTs
        collected: Dict[int, Dict[int, bytes]] = {}
        while len(collected) < self.n - self.t:
            done, _ = await asyncio.wait(output_tasks.keys(),
                                         return_when=asyncio.FIRST_COMPLETED)
            for fut in done:
                sid = output_tasks.pop(fut)
                try:
                    m_bytes, _ = fut.result()
                except asyncio.CancelledError:
                    continue
                msg = json.loads(m_bytes.decode())

                # verify VRF proof
                if not self._verify_vrf_proof(committee_label, msg.get("proof", {}), sid):
                    logger.warning("[GGATHER] bad proof from %d – ignored", sid)
                    continue

                U_j = {int(k): bytes.fromhex(h) for k, h in msg["U"].items()}
                collected[sid] = U_j
                logger.info("[GGATHER] received U′ from %d (|U′|=%d)",
                            sid, len(U_j))

        # 3)  compute union U and intersection T
        union_U: Dict[int, bytes] = {}
        for U_j in collected.values():
            union_U.update(U_j)

        key_sets = [set(U_j.keys()) for U_j in collected.values()]
        inter_keys = set.intersection(*key_sets) if key_sets else set()
        inter_T = {k: collected[next(iter(collected))][k] for k in inter_keys}

        self.U = union_U
        self.T = inter_T
        logger.info("[GGATHER] finished – |U|=%d, |T|=%d",
                    len(self.U), len(self.T))

        # 4)  tidy up pending tasks
        for fut in output_tasks:
            fut.cancel()
        for t in reactor_tasks:
            t.cancel()

    # ----------------------------------------------------------------------
    #  Generic helper: run n RBC 实例并收集 ≥ need 条 OUTPUT
    # ----------------------------------------------------------------------
    async def _collect_rbc(self, prefix_base: str,
                           my_payload: bytes,
                           need: int,
                           verify_label: Optional[bytes] = None):
        """return {sender_id: decoded_json}"""
        rbc, reactors, pending = {}, [], {}
        for sid in range(self.n):
            inst = YosoRBC(
                self.public_keys, self.private_key,
                self.pkbls, self.skbls,
                self.n, self.t, self.srs, self.my_id,
                self.send, self.recv,
                prefix=f"{prefix_base}_{sid}",
                shared_subscribe=(self._subscribe_task, self._subscribe_recv)
            )
            rbc[sid] = inst
            reactors.append(asyncio.create_task(inst.reactor()))
            pending[asyncio.create_task(inst.output_queue.get())] = sid

        if my_payload is not None:
            await rbc[self.my_id].sender(my_payload)

        out = {}
        while len(out) < need:
            done, _ = await asyncio.wait(pending.keys(),
                                         return_when=asyncio.FIRST_COMPLETED)
            for fut in done:
                sid = pending.pop(fut)
                try:
                    raw, _ = fut.result()
                    msg_dec = json.loads(raw.decode())

                    # --- VRF proof check for the *sending* committee ----
                    if verify_label is not None:
                        if not self._verify_vrf_proof(verify_label,
                                                      msg_dec.get("proof", {}),
                                                      sid):
                            logger.warning("[RBC] invalid proof from %d – drop", sid)
                            continue

                    out[sid] = msg_dec
                except Exception:
                    continue
        # 收尾
        for fut in pending: fut.cancel()
        for t in reactors:  t.cancel()
        return out

    # ------------------------------------------------------------------
    #  ΠWeakGradedSelectBlock – committee‑splitting helpers
    # ------------------------------------------------------------------
    async def _wgsb_first_round_yosorbc(self, coin: bytes):
        """
        First‑round candidate committee  (C_FirstRoundCandidate).
        Now: only send if in committee; do NOT wait for any RBC output.
        Returns Pk if in committee, else None.
        """
        Pk = None
        committee_label = b"WGSB_FR"
        in_comm, proof_self = self._is_committee_member(committee_label)
        if in_comm:
            ticket = {j: hashlib.sha256(str(j).encode() + coin).digest()
                      for j in self.U.keys()}
            Pk = min(ticket, key=ticket.get)
            payload = json.dumps(
                {"from": self.my_id, "Pk": Pk, "proof": proof_self}
            ).encode()
            await self._collect_rbc(
                prefix_base="WGSB_FR",
                my_payload=payload,
                need=0  # fire-and-forget send; do not wait for output
            )
        # All nodes (incl. non‑members) will learn Pk in the second phase.
        return Pk


    async def _wgsb_second_round_yosorbc(self,
                                         agreed_pk: int,
                                         b_i: int):
        """
        Second‑round candidate committee  (C_SecondRoundCandidate).
        1. Collect ≥ n−t FirstRoundCandidate messages (verifying VRF proofs).
        2. If in committee, compute agreed_pk, b_i and broadcast SecondRoundCandidate.
        3. Collect ≥ n−t SecondRoundCandidate messages (verifying VRF proofs).
        4. Return agreed_pk, n_true (#b_j=1).
        """
        # --- 1) gather FirstRoundCandidate msgs ------------------------
        fr_msgs = await self._collect_rbc(
            prefix_base="WGSB_FR",
            my_payload=None,
            need=self.n - self.t,
            verify_label=b"WGSB_FR"           # check proof of *senders*
        )

        identical = len({m["Pk"] for m in fr_msgs.values()}) == 1
        agreed_pk = list(fr_msgs.values())[0]["Pk"]
        b_i_local = 1 if identical else 0

        # --- 2) broadcast SecondRoundCandidate if in SR‑committee ------
        committee_label = b"WGSB_SR"
        in_comm, proof_self = self._is_committee_member(committee_label)
        if in_comm:
            payload = json.dumps(
                {"from": self.my_id,
                 "Pk":  agreed_pk,
                 "b":   b_i_local,
                 "proof": proof_self}
            ).encode()
            await self._collect_rbc(
                prefix_base="WGSB_SR",
                my_payload=payload,
                need=0
            )

        # --- 3) collect SecondRoundCandidate msgs (from SR committee) ---
        sr_msgs = await self._collect_rbc(
            prefix_base="WGSB_SR",
            my_payload=None,
            need=self.n - self.t,
            verify_label=b"WGSB_SR"
        )
        n_true = sum(1 for m in sr_msgs.values() if m.get("b"))
        return agreed_pk, n_true


    def _wgsb_finalize_output(self,
                              agreed_pk: int,
                              n_true: int) -> None:
        """
        Final committee  C_GradedSelectBlock  – compute (C_i, g_i)
        as in Fig 19 line 6 and store in self.C, self.g.
        """
        blk = self.U.get(agreed_pk, self.B_i)
        if n_true >= self.n - self.t and agreed_pk in self.T:
            self.C, self.g = blk, 2
        elif n_true > 0 and agreed_pk in self.U and agreed_pk not in self.T:
            self.C, self.g = blk, 1
        else:
            self.C, self.g = self.B_i, 0

        # logger.info("[WGSB] node %d – OUTPUT C=%s, g=%d", self.my_id, base64.b64encode(self.C).decode(), self.g)

    # ----------------------------------------------------------------------
    #  ΠWeakGradedSelectBlock (Fig. 19) – 单协程
    # ----------------------------------------------------------------------
    async def _weak_gradesel_yosorbc(self):
        """依赖已完成的 self.U、self.T，输出 self.C, self.g"""
        logger.info("[WGSB] node %d – starting WeakGradedSelectBlock", self.my_id)

        # 1) 共同硬币
        coin_input = [(k, v.hex()) for k, v in sorted(self.U.items())]
        coin = hashlib.sha256(json.dumps(coin_input).encode()).digest()
        logger.info("[WGSB] node %d – coin=%s", self.my_id, coin.hex())

        # 2) 第一轮：仅发送
        _ = await self._wgsb_first_round_yosorbc(coin)

        # 3) 第二轮：收集第一轮结果并可能再发送
        agreed_pk, n_true = await self._wgsb_second_round_yosorbc(None, None)

        # 4) 最终委员会 — 计算 (C_i, g_i)
        self._wgsb_finalize_output(agreed_pk, n_true)

    # ----------------------------------------------------------------------
    #  ΠStronglyStableGradedSelectBlock – helper: Upgrade‑1 (CUpgrade1)
    # ----------------------------------------------------------------------
    async def _ssgsb_upgrade1_yosorbc(self):
        """
        First upgrade committee (CUpgrade1).  
        If we are in the committee, broadcast (Upgrade1, B₁) and return.
        No collection is performed in this phase – CUpgrade2 will do that.
        """
        label_up1 = b"SSGSB_UP1"
        in_comm1, proof1 = self._is_committee_member(label_up1)
        if in_comm1:
            payload = json.dumps({
                "from":  self.my_id,
                "B":     self.C.hex(),
                "proof": proof1
            }).encode()
            # fire‑and‑forget: need=0  → just broadcast via RBC and move on
            await self._collect_rbc(prefix_base="SSGSB_UP1",
                                    my_payload=payload,
                                    need=0)
        return  # nothing to return – collection happens in Upgrade‑2

    # ----------------------------------------------------------------------
    #  ΠStronglyStableGradedSelectBlock – helper: Upgrade‑2 (CUpgrade2)
    # ----------------------------------------------------------------------
    async def _ssgsb_upgrade2_yosorbc(self):
        """
        Second upgrade committee (CUpgrade2).

        Steps
        -----
        1. Collect ≥ n−t Upgrade1 messages coming from CUpgrade1.
        2. Decide local (B*, h_i) where h_i∈{0,1}.
        3. If in CUpgrade2, broadcast (Upgrade2, B*, h_i).
        4. Return (B*, h_i) for the caller.
        """
        # 1) collect Upgrade1
        label_up1 = b"SSGSB_UP1"
        up1_msgs = await self._collect_rbc(prefix_base="SSGSB_UP1",
                                           my_payload=None,
                                           need=self.n - self.t,
                                           verify_label=label_up1)

        # 2) decide h_i & B*
        counter: Dict[str, int] = {}
        for m in up1_msgs.values():
            bh = m.get("B", "")
            counter[bh] = counter.get(bh, 0) + 1

        h_i = 0
        B_star_hex = ""
        for bh, cnt in counter.items():
            if bh and cnt >= self.n - self.t:
                h_i = 1
                B_star_hex = bh
                break
        logger.info("[SSGSB] node %d – decided B*=, h_i=%d",
                    self.my_id, h_i)

        # 3) broadcast Upgrade2 if we belong to CUpgrade2
        label_up2 = b"SSGSB_UP2"
        in_comm2, proof2 = self._is_committee_member(label_up2)
        if in_comm2:
            payload = json.dumps({
                "from":  self.my_id,
                "B":     B_star_hex,
                "h":     h_i,
                "proof": proof2
            }).encode()
            await self._collect_rbc(prefix_base="SSGSB_UP2",
                                    my_payload=payload,
                                    need=0)
        return B_star_hex, h_i


    # ----------------------------------------------------------------------
    #  ΠStronglyStableGradedSelectBlock (Fig. 20) – driver coroutine
    # ----------------------------------------------------------------------
    async def _strongly_stable_gradesel_yosorbc(self):
        """
        Execute Fig. 20 in three phases:
            (i)   Upgrade‑1 broadcast,
            (ii)  Upgrade‑2 collection + optional broadcast,
            (iii) Final collection & grade decision.
        Requires `self.C` to be set by the weak protocol beforehand.
        Overwrites `self.C` and `self.g` with strongly‑stable values.
        """
        # Phase (i) – CUpgrade1 just broadcasts
        await self._ssgsb_upgrade1_yosorbc()

        # Phase (ii) – CUpgrade2 collects Upgrade1 & maybe broadcasts Upgrade2
        await self._ssgsb_upgrade2_yosorbc()

        # Phase (iii) – everyone collects ≥ n−t Upgrade2 messages
        label_up2 = b"SSGSB_UP2"
        up2_msgs = await self._collect_rbc(prefix_base="SSGSB_UP2",
                                           my_payload=None,
                                           need=self.n - self.t,
                                           verify_label=label_up2)

        all_same_and_h1 = (
            all(m.get("h") == 1 for m in up2_msgs.values()) and
            len({m.get("B") for m in up2_msgs.values() if m.get("h") == 1}) == 1
        )

        if all_same_and_h1:
            # Everyone agrees on the exact same (B, h=1) → upgrade to g=2
            self.C = bytes.fromhex(next(m["B"] for m in up2_msgs.values()))
            self.g = 2
        elif any(m.get("h") == 1 for m in up2_msgs.values()):
            # Some evidence of soft‑grade, but not unanimous
            self.C = bytes.fromhex(next(m["B"] for m in up2_msgs.values()
                                        if m.get("h") == 1))
            self.g = 1
        else:
            # No upgrade proof – retain previous block, downgrade to g=0
            self.g = 0

        logger.info("[SSGSB] node %d – OUTPUT g=%d", self.my_id, self.g)

    # ----------------------------------------------------------------------
    #  ΠSelectBlock (Fig. 21) – outer driver that repeats StronglyStable
    # ----------------------------------------------------------------------
    async def _select_block_yosorbc(self, max_rounds: int = 10):
        """
        Implementation of Fig. 21 ΠSelectBlock.

        We start from the node’s current candidate block B_i (already justified)
        with grade 0, then iterate:

            for r = 1,2,…:
                – run Weak → StronglyStable once
                – if g = 2:  (rule 4‑1) output locally and echo
                – else      (rule 4‑2) wait for any echoed (B,2) and adopt

        The echo is realised with one RBC instance whose prefix is
        “SB_ECHO_<round>”.  Any node that first reaches g = 2 fires the echo;
        everyone else simply waits for ≥ 1 echo OUTPUT before the next round.
        """
        # --- Step 1 : initialise ------------------------------------------------
        self.gave_output: bool = False
        self.final_block: bytes | None = None
        self.final_round: int | None = None

        # Fig. 21 line 2 : (B^0_i , g^0_i = 0) – we piggy‑back on self.B_i
        self.C = getattr(self, "B_i", b"0")
        self.g = 0

        # --- Step 2 : iterate rounds -------------------------------------------
        for r in range(1, max_rounds + 1):
            if self.gave_output:
                break          # already decided in previous iteration

            # ---- 3.(a–c)  call Weak + StronglyStable once ----------------
            await self._weak_gradesel_yosorbc()
            await self._strongly_stable_gradesel_yosorbc()

            # ---------------------- rule 4‑1 ------------------------------
            if self.g == 2:
                self.gave_output = True
                self.final_block = self.C
                self.final_round = r

                echo_prefix = f"SB_ECHO_{r}"
                payload = json.dumps({
                    "from":  self.my_id,
                    "B":     self.C.hex(),
                    "g":     2,
                    "round": r
                }).encode()

                # fire‑and‑forget echo RBC (need = 0)
                await self._collect_rbc(
                    prefix_base=echo_prefix,
                    my_payload=payload,
                    need=0
                )
                logger.info("[SELECT] node %d – produced output in round %d",
                            self.my_id, r)
                break

            # ---------------------- rule 4‑2 ------------------------------
            echo_prefix = f"SB_ECHO_{r}"
            try:
                echo_msgs = await self._collect_rbc(
                    prefix_base=echo_prefix,
                    my_payload=None,
                    need=1          # wait for ≥ 1 echo
                )
            except Exception:
                echo_msgs = {}

            for m in echo_msgs.values():
                if m.get("g") == 2:
                    self.gave_output = True
                    self.final_block = bytes.fromhex(m["B"])
                    self.final_round = m.get("round", r)
                    logger.info("[SELECT] node %d – adopted echoed block in round %d",
                                self.my_id, self.final_round)
                    break

            # prepare next iteration – keep (self.C, self.g) as (B^{r}_i, g^{r}_i)

        if not self.gave_output:
            logger.warning("[SELECT] node %d – max_rounds reached without g=2", self.my_id)
        else:
            logger.info("[SELECT] node %d – FINAL OUTPUT  (round=%d, |B|=%d)",
                        self.my_id, self.final_round, len(self.final_block or b""))

    # # ----------------------------------------------------------------------
    # #  Generic helper: run n RBC 实例并收集 ≥ need 条 OUTPUT
    # # ----------------------------------------------------------------------
    # async def _collect_rbc(self, prefix_base: str,
    #                        my_payload: bytes,
    #                        need: int):
    #     """return {sender_id: decoded_json}"""
    #     rbc, reactors, pending = {}, [], {}
    #     for sid in range(self.n):
    #         inst = YosoRBC(
    #             self.public_keys, self.private_key,
    #             self.pkbls, self.skbls,
    #             self.n, self.t, self.srs, self.my_id,
    #             self.send, self.recv,
    #             prefix=f"{prefix_base}_{sid}",
    #             shared_subscribe=(self._subscribe_task, self._subscribe_recv)
    #         )
    #         rbc[sid] = inst
    #         reactors.append(asyncio.create_task(inst.reactor()))
    #         pending[asyncio.create_task(inst.output_queue.get())] = sid

    #     if my_payload is not None:
    #         await rbc[self.my_id].sender(my_payload)

    #     out = {}
    #     while len(out) < need:
    #         done, _ = await asyncio.wait(pending.keys(),
    #                                      return_when=asyncio.FIRST_COMPLETED)
    #         for fut in done:
    #             sid = pending.pop(fut)
    #             try:
    #                 raw, _ = fut.result()
    #                 out[sid] = json.loads(raw.decode())
    #             except Exception:
    #                 continue
    #     # 收尾
    #     for fut in pending: fut.cancel()
    #     for t in reactors:  t.cancel()
    #     return out
    
    # # ----------------------------------------------------------------------
    # #  ΠWeakGradedSelectBlock (Fig. 19) – 单协程
    # # ----------------------------------------------------------------------
    # async def _weak_gradesel_yosorbc(self):
    #     """依赖已完成的 self.U、self.T，输出 self.C, self.g"""
    #     logger.info("[WGSB] node %d – starting WeakGradedSelectBlock", self.my_id)
    #     # 1) 共同硬币
    #     # 将 bytes 转成十六进制字符串后再做 JSON 序列化，避免 “bytes not JSON serializable” 错误
    #     coin_input = [(k, v.hex()) for k, v in sorted(self.U.items())]
    #     coin = hashlib.sha256(json.dumps(coin_input).encode()).digest()
    #     logger.info("[WGSB] node %d – coin=%s", self.my_id, coin.hex())
    #     # 选第一轮候选 Pk
    #     ticket = {j: hashlib.sha256(str(j).encode() + coin).digest()
    #               for j in self.U.keys()}
    #     Pk = min(ticket, key=ticket.get)
    #     logger.info("[WGSB] node %d – first-round Pk=%d", self.my_id, Pk)

    #     # 2) 第一轮广播
    #     fr_payload = json.dumps({"from": self.my_id, "Pk": Pk}).encode()
    #     fr = await self._collect_rbc("WGSB_FR", fr_payload, need=self.n - self.t)
    #     equal = len({m["Pk"] for m in fr.values()}) == 1
    #     agreed_pk = list(fr.values())[0]["Pk"] if equal else Pk
    #     b_i = equal

    #     # 3) 第二轮广播
    #     sr_payload = json.dumps({"from": self.my_id,
    #                              "Pk": agreed_pk,
    #                              "b":  b_i}).encode()
    #     sr = await self._collect_rbc("WGSB_SR", sr_payload, need=self.n - self.t)
    #     n_true = sum(1 for m in sr.values() if m.get("b"))

    #     # 4) 输出
    #     blk = self.U.get(agreed_pk, self.B_i)
    #     if n_true >= self.n - self.t and agreed_pk in self.T:
    #         self.C, self.g = blk, 2
    #     elif n_true > 0 and agreed_pk in self.U and agreed_pk not in self.T:
    #         self.C, self.g = blk, 1
    #     else:
    #         self.C, self.g = self.B_i, 0
    #     logger.info("[WGSB] node %d – OUTPUT g=%d", self.my_id, self.g)
    
    # ----------------------------------------------------------------------
    #  One gather round
    # ----------------------------------------------------------------------
    async def _one_round(self, r: int):
        """
        Execute round *r* (1‑based).  Uses tag  f"GATHER_R{r}_{self.my_id}".
        Broadcast current U_{r‑1}, collect ≥ n‑t replies, take union.
        """
        # prefix = f"GATHER_R{r}_{self.my_id}"
        prefix = f"GATHER_R{r}"
        send_bcast = self._mk_broadcast(prefix)
        recv_tag   = self._recv(prefix)

        # Before broadcasting, check committee membership and get proof
        in_comm, proof = self._is_committee_member(prefix.encode())
        logger.info("[GATHER] node %d, round %d, in committee: %s",
                    self.my_id, r, in_comm)
        if not in_comm:
            return  # not in committee, skip broadcast

        # 1) Broadcast U_{r‑1}
        payload = json.dumps({
            "from": self.my_id,
            # encode bytes as hex for JSON transport
            "U": {str(k): v.hex() for k, v in self.U.items()},
            "proof": proof
        }).encode()
        await send_bcast(payload)

        # 2) Collect ≥ n‑t messages (including our own)
        collected: Dict[int, Dict[int, bytes]] = {self.my_id: self.U}
        logger.info("[GATHER] node %d, round %d, collecting messages", self.my_id, r)

        while len(collected) < self.n - self.t:
            logger.info("[GATHER] node %d, round %d, waiting for messages",
                         self.my_id, r)
            sender, raw = await recv_tag()          # block
            logger.info("[GATHER] node %d, round %d, received from %d",
                         self.my_id, r, sender)
            msg = json.loads(raw.decode())
            sid = msg["from"]
            logger.info("[GATHER] node %d, round %d, received from %d",
                         self.my_id, r, sid)
            # VRF proof verification
            if not self._verify_vrf_proof(prefix.encode(), msg["proof"], sid):
                logger.warning("[GATHER] bad VRF from %d – ignored", sid)
                continue
            if sid in collected:                    # duplicate
                continue
            # Parse U_r‑1  back into  Dict[int, bytes]
            U_j = {int(k): bytes.fromhex(h) for k, h in msg["U"].items()}
            logger.info("[GATHER] node %d, round %d, U_j from %d: |U_j| = %d",
                         self.my_id, r, sid, len(U_j))
            # (Stub) Justifier check
            if not self._justifier(U_j):
                logger.warning("[GATHER] bad justifier from node %d – ignored", sid)
                continue
            collected[sid] = U_j

        # 3) Merge all collected sets
        logger.info("[GATHER] node %d, round %d, collected %d messages",    
                    self.my_id, r, len(collected))
        new_U: Dict[int, bytes] = {}
        for U_j in collected.values():
            new_U.update(U_j)           # union (later entries overwrite duplicates)
        self.U = new_U
        logger.info("[GATHER] round %d finished – |U_%d| = %d",
                    r, r, len(self.U))

    # ------------------------------------------------------------------
    #  Context‑manager / cleanup utilities
    # ------------------------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # nothing special to clean up for this prototype
        return False

    def kill(self):
        # placeholder for symmetry with caller code
        pass
    
    # 由其他协程调用，执行 gather 逻辑
    async def _execute_gather(self):
        """
        Execute YOSO-RBC based gather rounds (rounds 1 to 3).
        """
        # Short sleep so that peers have time to subscribe
        await asyncio.sleep(0.1)
        for r in range(1, 4):
            await self._one_round_yosorbc(r)

    # ----------------------------------------------------------------------
    #  Public coroutine
    # ----------------------------------------------------------------------
    # async def run_gather(self, node_communicator, *, cleanup: bool = True):
    async def run_gather(self, node_communicator):
        """
        Drives 3 rounds and then terminates.  Returns when U₃ is ready.
        """
        # Short sleep so that peers have time to subscribe
        await asyncio.sleep(0.1)

        yosorbc_start = time.time()
        for r in range(1, 4):           # r = 1, 2, 3
            # await self._one_round(r)
            one_round_yosorbc_start = time.time()
            await self._one_round_yosorbc(r)
            one_round_yosorbc_end = time.time()
            logger.info(f"[GATHER] node {self.my_id} YOSORBC round {r} time: {one_round_yosorbc_end - one_round_yosorbc_start:.3f} seconds")

        yosorbc_end = time.time()
        logger.info(f"[GATHER] node {self.my_id} YOSORBC gather time: {yosorbc_end - yosorbc_start:.3f} seconds")

        logger.info("[GATHER] node %d completed 3 rounds – |U|=, |T|=",
                    self.my_id)
        # ---- extra causal‑cast round for graded gather ----
        graded_start = time.time()
        await self._graded_gather_yosorbc()
        graded_end = time.time()
        logger.info(f"[GGATHER] node {self.my_id} YOSORBC graded gather time: {graded_end - graded_start:.3f} seconds")
        logger.info("[GGATHER] node %d completed ΠGradedGather – |U|=, |T|=",
                    self.my_id)

        # await self._weak_gradesel_yosorbc()
        # await self._strongly_stable_gradesel_yosorbc()
        select_start = time.time()
        await self._select_block_yosorbc()
        select_end = time.time()
        logger.info(f"[SELECT] node {self.my_id} YOSORBC select block time: {select_end - select_start:.3f} seconds")
        logger.info("[SELECT] node %d completed ΠSelectBlock – C=, g=%d",
                    self.my_id, self.g)

        self._subscribe_task.cancel()       
        
        if node_communicator is not None:
            bytes_sent = node_communicator.bytes_sent
            for k,v in node_communicator.bytes_count.items():
                logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
            logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")

        # Gracefully shut down receive task and return so the process can exit
        return