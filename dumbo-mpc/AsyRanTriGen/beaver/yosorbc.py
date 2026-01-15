"""
Minimal YOSO‑style Reliable Broadcast (RBC) prototype.

* Network size      : M = 4
* Committee size    : n = 3t + 1 = 4  (⇒ t = 1)
* We deliberately **omit** Reed–Solomon encoding — each committee
  member simply relays the *whole* message `m`.
* Committees C_echo and C_ready are, for this prototype, *identical*
  and contain every node (0‑based indices 0 … 3).  In a production
  system each node would attach its VRF proof to every broadcast so
  that outsiders can verify membership; the plumbing for doing this
  is sketched but the security‑critical VRF calls are *stubbed* so
  the code can run even before `libvrf.so` is available.

The public API is just two coroutines:
    •  YosoRBC.sender(msg)            – run by the designated sender P_s
    •  YosoRBC.reactor()              – run by *every* node
"""
import sys
import base64
import pickle
import asyncio
import hashlib
import json
import logging
import math
from typing import Dict, Tuple
from Crypto.Util.number import long_to_bytes
from ctypes import *
import numpy as np
from reedsolo import RSCodec, ReedSolomonError
from collections import defaultdict
from typing import DefaultDict
import time

# ---------------------------------------------------------------------------
#  Hard‑coded VRF key material for the 4‑node demo
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
#  Messaging helpers – identical to those used in batch_multiplication.py
# ---------------------------------------------------------------------------
from beaver.utils.misc import wrap_send, subscribe_recv

# ---------------------------------------------------------------------------
#  VRF FFI (optional).  If libvrf.so is absent the code falls back to stubs.
# ---------------------------------------------------------------------------
try:

    lib_bulletproof = CDLL("./libbulletproofs_amcl.so")
    lib_bulletproof.pyVrfProve.argtypes = [c_char_p]
    lib_bulletproof.pyVrfProve.restype  = c_void_p

    lib_bulletproof.pyVrfVerify.argtypes = [c_char_p]
    lib_bulletproof.pyVrfVerify.restype = c_void_p

    lib_bulletproof.pyFreeString.argtypes = [c_void_p]  # ✅ 必须匹配！
    lib_bulletproof.pyFreeString.restype = None
except OSError:
    lib_bulletproof = None


# ---------------------------------------------------------------------------
#  Constants – for this demo everything is hard‑wired.
# ---------------------------------------------------------------------------
M  = 4               # network size
t  = 1               # Byzantine threshold
n  = 3 * t + 1       # committee size  (= 4)
assert n == M, "prototype assumes C_echo == C_ready == whole network"




def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# 新增 RS 编码函数（参考 potqrbc 的实现）
def rs_encode(m: bytes, k: int, n: int) -> list:
    rsc = RSCodec(n - k)
    padlen = k - (len(m) % k)
    m += padlen * bytes([k - padlen])
    mlen = len(m) // k
    blocks = [m[i * k: (i + 1) * k] for i in range(mlen)]
    stripes = [rsc.encode(block) for block in blocks]
    nstripes = np.array(stripes)
    return nstripes.T.tolist()   # 每个元素为 bytes 数组

# 新增 RS 解码函数（参考 potqrbc 的实现）
def rs_decode(k: int, n: int, shares: list) -> bytes:
    """
    Reconstruct the original message from `n` stripes.
    Each element in `shares` is `bytes` (stripe) or `None`.
    Need ≥ k non-None stripes.
    """
    rsc = RSCodec(n - k)

    # 把 bytes → List[int]；缺失的用 None
    stripes_ints = [
        list(s) if s is not None else None
        for s in shares
    ]

    # 拿到编码块长度
    first = next(x for x in stripes_ints if x is not None)
    elen  = len(first)

    # 构造 n 列矩阵；空位填 0
    columns = [
        stripe if stripe is not None else [0] * elen
        for stripe in stripes_ints
    ]

    code_words = np.array(columns).T          # shape: (elen, n)

    message_blocks = []
    for word in code_words:                   # 每行长度 == n
        # 直接把 List[int] 喂给 reedsolo
        message_blocks.append(rsc.decode(list(word))[0])

    m = b"".join(message_blocks)
    padlen = k - m[-1]
    return m[:-padlen]


# ---------------------------------------------------------------------------
#  Main class
# ---------------------------------------------------------------------------
class YosoRBC:
    def __init__(self,
                 public_keys, private_key,      # PKI
                 pkbls, skbls,                  # BLS
                 n, t, srs, my_id,              # Committee Size/Threshold
                 send, recv,
                 prefix: str = "RBC", shared_subscribe=None):          # ← NEW

        global logger
        logfile = f'./log/logs-{my_id}.log'

        logging.basicConfig(
            level=logging.INFO,
            format = '%(asctime)s:[%(filename)s:%(lineno)s]:[%(levelname)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            filename=logfile,  
            filemode='w'
        )
        # logging.basicConfig(
        #     level=logging.INFO,
        #     format='%(asctime)s [%(levelname)s] %(message)s',
        #     handlers=[logging.StreamHandler(sys.stdout),
        #             logging.FileHandler(logfile, mode='w')]
        # )

        logger = logging.getLogger(__name__)

        self.public_keys, self.private_key, self.pkbls, self.skbls = (public_keys, private_key, pkbls, skbls)
        # ------------------------------------------------------------------
        #  Per‑instance tag prefix  (allows many concurrent RBC sessions)
        # ------------------------------------------------------------------
        self.prefix = prefix
        def _tag(kind: str) -> str:
            return f"{self.prefix}_{kind}"
        self._tag = _tag
        # Node identifier (needed throughout the class)
        self.n, self.t, self.srs, self.my_id = (n, t, srs, my_id)
        self.send, self.recv = (send, recv)
        # Add hardcoded VRF keys for the 4-node demo
        self.vrf_sk_list = VRF_SK_LIST_DEC
        self.vrf_pk_list = VRF_PK_LIST
        # Create a mechanism to split the `recv` channels based on `tag`
        # self.subscribe_recv_task, self.subscribe_recv = subscribe_recv(recv)
        # # Helper to fetch a tag‑scoped receiver just like we do for send.
        # def _recv(tag):
        #     return self.subscribe_recv(tag)
        # self._recv = _recv

        # ------------------------------------------------------------------
        # Glue code: ① 若调用方传进共享 dispatcher，就重用；
        #            ② 否则自己再开一个。
        # ------------------------------------------------------------------
        if shared_subscribe is None:
            self._subscribe_task, self._subscribe_recv = subscribe_recv(recv)
        else:
            self._subscribe_task, self._subscribe_recv = shared_subscribe

        def _recv(tag):
            return self._subscribe_recv(tag)
        self._recv = _recv

        # Wrap the point-to-point send into a broadcast function
        def _mk_broadcast(tag: str):
            p2p_send = wrap_send(tag, send)  # expects (dest, data)

            async def broadcast(msg: bytes):
                for dest in range(self.n):
                    p2p_send(dest, msg)
            return broadcast
        self.get_send = _mk_broadcast

        # ↓ 新增：按 hash 计数
        self._echo_hash_cnt = defaultdict(int)

        # # Create a mechanism to split the `send` channels based on `tag`
        # def _send(tag):
        #     return wrap_send(tag, send)
        # self.get_send = _send
        self.output_queue = asyncio.Queue()
        # ------------------------------------------------------------------
        #  Pending‑pool & block‑production helpers
        # ------------------------------------------------------------------
        self.pending_pool: list[bytes] = []   # locally buffered RBC payloads
        self.block_height: int = 0            # monotonically increasing block ID
        # 新增：存储收到的 echo share，key 为发送者 id
        self._echo_shares = {}

        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": self.my_id}
        )

        #  -------------------  RBC state variables  --------------------
        self._send_seen   = False            # have we processed the first SEND yet?
        self._msg         = None             # cached payload bytes
        self._hash        = None             # SHA‑256(m)
        self._echo_recv   : Dict[int, str]  = {}  # sender_id -> hash
        self._ready_recv  : Dict[int, str]  = {}  # sender_id -> hash
        self._outputted   = False

        # (share_hex, hash) → #ECHO  (need ≥ 2t+1 matching pair)
        self._echo_count: DefaultDict[Tuple[str, str], int] = defaultdict(int)
        self._ready_sent = False                                     # did we already broadcast READY?
        self._T_h: Dict[int, bytes] = {}                             # READY shares collected (sender → share)
        # Buffers to postpone locking the hash until ≥ t+1 READY with same h
        self._ready_temp: DefaultDict[str, Dict[int, bytes]] = defaultdict(dict)

    def _get_generator_hex(self):
        if hasattr(self, "_cached_g_hex"):
            return self._cached_g_hex
        pk_dict = json.loads(self.srs["Pk"].decode("utf-8"))
        # logger.info("self.srs: %s", self.srs)
        g0 = pk_dict["G1_g"][0]
        gx = long_to_bytes(int(g0["X"]), 48)
        gy = long_to_bytes(int(g0["Y"]), 48)
        self._cached_g_hex = (b'\x04' + gx + gy).hex()
        return self._cached_g_hex
    
    # ......................................................................
    #  VRF stubs / helpers
    # ......................................................................
    def _is_committee_member(self, label: bytes) -> Tuple[bool, str]:
        """
        Dummy committee selection:
            – For this prototype every node is in every committee.
            – Returns (True, proof_json) so that downstream code
              can pretend it verified a VRF proof.
        """
        if lib_bulletproof is None:
            return True, "{}"               # no VRF library – always succeed

        # msg = "43066057178372115162090031665738480497785504495963485110743715314730498099898"
        # msg_hex = hex(int(msg))[2:]  # 去掉 0x 前缀
        # Encode the VRF label itself (bytes) as a hex string to use as the message
        msg_hex = label.hex()
        logger.info("msg_hex: %s", msg_hex)

        # # logger.info("self.private_key: %s", self.private_key)
        # raw = self.private_key.decode("utf-8")
        # inner = json.loads(raw)
        # key_dict = json.loads(inner)
        # # logger.info("key_dict: %s", key_dict)

        # # 1. 取出 Base64
        # sk_b64 = key_dict[str(self.my_id)]

        # # 2. 解 Base64 → 去掉内层引号
        # sk_str = base64.b64decode(sk_b64).decode('utf-8').strip('"')

        # # 3. 转十进制 → ZR
        # sk_int  = int(sk_str)
        # sk_hex = hex(sk_int)[2:]  # 去掉 0x 前缀

        # --- use hard‑coded VRF secret key --------------------------------
        sk_int = int(self.vrf_sk_list[self.my_id])
        sk_hex = hex(sk_int)[2:]
        logger.info("sk_hex  : %s", sk_hex)

        # logger.info("self.public_keys: %s", self.public_keys)
        
        payload = {
                "sk": sk_hex,
                "msg": msg_hex, 
                "g":   self._get_generator_hex()
            }
        json_input = json.dumps(payload).encode("utf-8")
        ptr_proof = lib_bulletproof.pyVrfProve(json_input)
        proof = json.loads(string_at(ptr_proof).decode("utf-8"))
        # logger.info("proof  : %s", proof)
        lib_bulletproof.pyFreeString(ptr_proof)

        return True, proof             # NOTE: production code would do hash‑based thresholding

    # ......................................................................
    #  VRF verification helper
    # ......................................................................
    def _verify_vrf_proof(self, label: bytes, proof: dict, sender_id: int) -> bool:
        """
        Verify a VRF proof coming from *sender_id* for the given *label*.
        Falls back to “accept‑all” if the FFI library is not available.
        """
        if lib_bulletproof is None:
            return True                       # no VRF library – trust by default

        msg_hex = label.hex()

        # -- look up sender’s hard‑coded VRF public key --------------------
        pk_entry = self.vrf_pk_list[sender_id]   # {"X": "...", "Y": "..."}
        # logger.info("pk_entry: %s", pk_entry)
        # logger.info("sender_id: %s", sender_id)
        gx_dec = int(pk_entry["X"])
        gy_dec = int(pk_entry["Y"])
        gx_bytes = long_to_bytes(gx_dec, 48)
        gy_bytes = long_to_bytes(gy_dec, 48)
        # 0x04 || X || Y  — uncompressed point encoding
        uncompressed_pk = b'\x04' + gx_bytes + gy_bytes
        pk_hex = uncompressed_pk.hex()
        # logger.info("pk_hex: %s", pk_hex)
        # logger.info("proof beta: %s", proof["beta"])
        # logger.info("proof c: %s", proof["c"])
        # logger.info("proof s: %s", proof["s"])

        # Parse beta as a tuple "(X_hex,Y_hex)"
        beta_str = proof["beta"].strip("()")
        beta_x_hex, beta_y_hex = beta_str.split(",")
        beta_x_bytes = bytes.fromhex(beta_x_hex)
        beta_y_bytes = bytes.fromhex(beta_y_hex)
        uncompressed_beta = b'\x04' + beta_x_bytes + beta_y_bytes
        beta_hex = uncompressed_beta.hex()
        # logger.info("beta_hex: %s", beta_hex)

        # -- call FFI -------------------------------------------------------
        payload = {
            "pk":   pk_hex,
            "msg":  msg_hex,
            "beta": beta_hex,
            "c":    proof["c"],
            "s":    proof["s"], 
            "g":   self._get_generator_hex()
        }
        json_input = json.dumps(payload).encode("utf-8")
        ptr = lib_bulletproof.pyVrfVerify(json_input)
        raw = string_at(ptr).decode("utf-8")
        logger.info("VRF verify result: %s", raw)
        lib_bulletproof.pyFreeString(ptr)

        # library returns either plain "true"/"false" or {"ok": true} JSON
        try:
            res = json.loads(raw)
            return bool(res.get("valid", res.get("ok", False)))
        except Exception:
            return raw.strip().lower() in ("true", "1")

    # ......................................................................
    #  Pending pool / block‑packaging logic
    # ......................................................................
    def _predicate_W(self) -> bool:
        """
        Placeholder predicate for when a block can be formed.
        For now it always returns True; plug in real logic here later.
        """
        return True

    def _maybe_package_block(self):
        """
        If predicate W is satisfied, turn the current pending‑pool into a block.
        Right now we just log the block and clear the pool; hooking up an ACS
        instance can be done later where indicated.
        """
        if not self.pending_pool:
            return
        if self._predicate_W():
            block = {
                "height": self.block_height,
                "messages": self.pending_pool.copy(),
            }
            logger.info("[BLOCK] packaged block %d with %d msgs",
                        self.block_height, len(self.pending_pool))
            # TODO: replace the logging statement with a call to ACS.
            self.pending_pool.clear()
            self.block_height += 1

    def _add_to_pending(self, payload: bytes):
        """
        Add a freshly delivered RBC payload to the local pending pool and
        trigger block‑packaging if the predicate is met.
        """
        self.pending_pool.append(payload)
        self._maybe_package_block()

    # ......................................................................
    #  API: sender coroutine
    # ......................................................................
    async def sender(self, m: bytes):
        """Executed by P_s to initiate RBC with payload `m`."""
        # logger.info("[SEND] node %d sending initial message %s", self.my_id, m)
        tag = self._tag("SEND")
        # logger.info("[SEND] tag: %s", tag)
        send = self.get_send(tag)
        await send(json.dumps({
            "sender": self.my_id,
            "payload": m.hex(),
        }).encode())            # broadcast to all

        logger.info("[SEND] broadcasted initial message (%d bytes)", len(m))

    # ......................................................................
    #  API: reactor coroutine – every node runs exactly ONE instance
    # ......................................................................
    async def reactor(self):
        send_echo  = self.get_send(self._tag("ECHO"))
        send_ready = self.get_send(self._tag("READY"))

        recv_send   = self._recv(self._tag("SEND"))
        logger.info("[REACTOR] node %d waiting for SEND, %s", self.my_id, self._tag("SEND"))
        recv_echo   = self._recv(self._tag("ECHO"))
        recv_ready  = self._recv(self._tag("READY"))

        tasks = {
            asyncio.create_task(recv_send()):  "SEND",
            asyncio.create_task(recv_echo()):  "ECHO",
            asyncio.create_task(recv_ready()): "READY",
        }
        out_task_start = time.time()
        while tasks:
            done, _ = await asyncio.wait(tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
            task_start = time.time()
            for t in done:
                tag_kind = tasks.pop(t)
                try:
                    sender, raw = t.result()  # raw: bytes
                except asyncio.CancelledError:
                    continue

                msg = json.loads(raw.decode())

                if tag_kind == "SEND":
                    logger.info("[SEND] node %d received SEND from %d", self.my_id, sender)
                    await self._handle_send(msg, send_echo)
                    tasks[asyncio.create_task(recv_send())] = "SEND"
                elif tag_kind == "ECHO":
                    logger.info("[ECHO] node %d received ECHO from %d", self.my_id, sender)
                    await self._handle_echo(msg, send_ready)
                    tasks[asyncio.create_task(recv_echo())] = "ECHO"
                elif tag_kind == "READY":
                    logger.info("[READY] node %d received READY from %d", self.my_id, sender)
                    await self._handle_ready(msg)
                    tasks[asyncio.create_task(recv_ready())] = "READY"
            task_end = time.time()
            logger.info("[BENCHMARK] node %d reactor loop iteration time: %f seconds", self.my_id, task_end - task_start)
            if self._outputted:
                for t in tasks.keys():
                    t.cancel()
                out_task_end = time.time()
                logger.info("[BENCHMARK] node %d total RBC time: %f seconds", self.my_id, out_task_end - out_task_start)
                return

    # ......................................................................
    #  Handlers
    # ......................................................................
    async def _handle_send(self, msg, send_echo):
        """
        Handle the <PROPOSE, M> message (tag == RBC_SEND).
        Only the _origin_ node does RS‑encoding; everyone else just forwards
        the share intended for each receiver j.
        """
        handle_send_start = time.time()
        if self._send_seen:
            return
        self._send_seen = True

        m_hex = msg["payload"]
        self._msg  = bytes.fromhex(m_hex)
        self._hash = _hash(self._msg)

        # Committee filter (VRF): skip if not in YOSO‑echo committee
        echo_label = f"{self.prefix}:ECHO".encode()
        logger.info("[SEND] node %d is checking committee membership for ECHO %s", self.my_id, echo_label)
        in_committee, proof = self._is_committee_member(echo_label)
        if not in_committee:
            return

        # ------------------------------------------------------------------
        # Step 8‑10 of Alg‑4: every node that accepts (PROPOSE,M) does
        # M' := RSENC(M,n,t+1)  and unicasts  (ECHO, m_j, h)  to each P_j.
        # ------------------------------------------------------------------
        shares = rs_encode(self._msg, self.t + 1, self.n)
        shares_hex = [bytes(s).hex() for s in shares]

        # Use point‑to‑point send (NOT broadcast!) so that each receiver
        # obtains exactly its own share m_j.
        p2p_send = wrap_send(self._tag("ECHO"), self.send)
        for dest in range(self.n):
            echo_msg = json.dumps({
                "hash": self._hash,
                "from": self.my_id,
                "share": shares_hex[dest],
                "proof": proof
            }).encode()
            p2p_send(dest, echo_msg)

        logger.info("[ECHO] node %d unicasted its shares", self.my_id)
        handle_send_end = time.time()
        logger.info("[BENCHMARK] node %d handle_send time: %f seconds", self.my_id, handle_send_end - handle_send_start)
    
    async def _handle_echo(self, msg, send_ready):
        handle_echo_start = time.time()
        sender = msg["from"]

        # 1) committee membership check
        echo_label = f"{self.prefix}:ECHO".encode()
        if not self._verify_vrf_proof(echo_label, msg["proof"], sender):
            logger.warning("[ECHO] invalid VRF proof from %d – discarded", sender)
            return

        h        = msg["hash"]
        share_hex = msg["share"]            # this node's share sent by *sender*
        logger.info("[ECHO] node %d received ECHO from %d with hash %s", self.my_id, sender, h)

        # 1) 统计满足同一 hash 的 ECHO 条数
        self._echo_hash_cnt[h] += 1
        if self._echo_hash_cnt[h] >= 2 * self.t + 1:
            if self._hash is None:
                self._hash = h
            elif h != self._hash:
                logger.warning("[ECHO] conflicting hash after threshold – discarded")
                return

            # READY 只发一次
            if not self._ready_sent:
                self._ready_sent = True
                ready_label = f"{self.prefix}:READY".encode()
                in_comm, proof_r = self._is_committee_member(ready_label)
                if not in_comm:
                    return
                await send_ready(json.dumps({
                    "hash": h,
                    "from": self.my_id,
                    "share": share_hex,    # 带上自己那份方便解码
                    "proof": proof_r
                }).encode())
                logger.info("[READY] node %d broadcast READY", self.my_id)

        handle_echo_end = time.time()
        logger.info("[BENCHMARK] node %d handle_echo time: %f seconds", self.my_id, handle_echo_end - handle_echo_start)
        # # ------------------------------------------------------------------
        # # Count matching (share_hex , h) pairs ; send READY after ≥ 2t+1
        # # ------------------------------------------------------------------
        # key = (share_hex, h)
        # self._echo_count[key] += 1
        # cnt = self._echo_count[key]

        # # When we have 2t+1 identical ECHO for this pair …
        # if cnt >= (2 * self.t + 1):
        #     # Lock‑in the hash if it was still unset
        #     if self._hash is None:
        #         self._hash = h
        #     # If we already committed to another hash, discard
        #     elif h != self._hash:
        #         logger.warning("[ECHO] conflicting hash after threshold – discarded")
        #         return

        #     # Broadcast READY only once
        #     if not self._ready_sent:
        #         self._ready_sent = True
        #         in_comm, proof_r = self._is_committee_member(b"YOSOready")
        #         if not in_comm:
        #             return
        #         await send_ready(json.dumps({
        #             "hash": h,
        #             "from": self.my_id,
        #             "share": share_hex,
        #             "proof": proof_r
        #         }).encode())
        #         logger.info("[READY] node %d broadcast READY with its share", self.my_id)
    
    async def _handle_ready(self, msg):
        handle_ready_start = time.time()
        sender = msg["from"]

        ready_label = f"{self.prefix}:READY".encode()
        if not self._verify_vrf_proof(ready_label, msg["proof"], sender):
            logger.warning("[READY] invalid VRF proof from %d – discarded", sender)
            return

        h         = msg["hash"]
        share_hex = msg["share"]

        # ---------------------------------------------------------------
        # 1)  Buffer shares by their hash until ≥ t+1 READY agree
        # ---------------------------------------------------------------
        tmp = self._ready_temp[h]
        if sender in tmp:
            return                           # duplicate READY from same sender
        tmp[sender] = bytes.fromhex(share_hex)

        # If we have not committed to any hash yet, wait for a quorum first
        if self._hash is None:
            if len(tmp) < self.t + 1:
                return                       # need more READY before locking‑in
            # Lock‑in the hash now
            self._hash = h
            self._T_h.update(tmp)            # seed the main share map
        else:
            # Already committed – ignore READY with a different hash
            if h != self._hash:
                logger.warning("[READY] hash %s ≠ committed %s – discarded", h, self._hash)
                return
            # … otherwise fall through and add to self._T_h

        # 2) store share (only once per sender)
        if sender not in self._T_h:
            self._T_h[sender] = bytes.fromhex(share_hex)

        # 3) attempt error‑correction once we have enough shares
        #    Alg‑4 loops over r=0..t; here we try every time |T_h| grows.
        error_correction_start = time.time()
        if len(self._T_h) >= self.t + 1:
            try:
                # Build stripes list indexed by node id; unknown => None
                stripes = [None] * self.n
                for j, sh in self._T_h.items():
                    stripes[j] = sh
                    # logger.info("sh: %s", sh)
                # logger.info("stripes: %s", stripes)
                # Decode the message using Reed–Solomon
                # Note: t+1 is the number of data blocks, n is the total number of shares
                m_rec = rs_decode(self.t + 1, self.n, stripes)
                if _hash(m_rec) == self._hash:
                    logger.info("[OUTPUT] decoded M (%d bytes)", len(m_rec))
                    # Store the delivered message in the local pending pool
                    self._add_to_pending(m_rec)
                    self._msg = m_rec
                    self._outputted = True
                    await self.output_queue.put((self._msg, self._hash))
            except ReedSolomonError as e:
                logger.error("RS decode failed with %d shares: %s", len(self._T_h), e)
        error_correction_end = time.time()
        logger.info("[BENCHMARK] node %d error_correction time: %f seconds", self.my_id, error_correction_end - error_correction_start)
        handle_ready_end = time.time()
        logger.info("[BENCHMARK] node %d handle_ready time: %f seconds", self.my_id, handle_ready_end - handle_ready_start)
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

    # ..................................................................
    #  High‑level driver invoked by run_yosorbc.py
    # ..................................................................
    async def run_yosorbc(self, node_communicator):
        """
        Spawn the reactor and (if we are node 0) act as the sender
        with a dummy payload.  Completes once OUTPUT is delivered.
        """
        reactor_task = asyncio.create_task(self.reactor())

        # Give peers a moment to subscribe
        await asyncio.sleep(0.1)

        if self.my_id == 0:
            await self.sender(b"Hellofromnode0")  # P_s sends initial message

        # Wait until reactor terminates (it returns after OUTPUT)
        await reactor_task

        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")

        # Gracefully shut down receive task and return so the process can exit
        self.subscribe_recv_task.cancel()
        return