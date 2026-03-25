"""
gradedgather.py
===============

完整实现 **ΠGradedGather** (Fig. 18) —— 相当于在三轮 ΠGather 之后，
再额外做一次 “因果广播” 以得到 (U, T) 的 *union & intersection*。

• 本文件只依赖 g → `beaver.gather.YosoGather` 以及
  rbc → `beaver.yosorbc.YosoRBC`（二者都已实现）。
• “Justifier” 检查继续沿用 YosoGather 里的 stub（始终返回 True）。

用法示例
--------

```python
gg = GradedGather(public_keys, private_key,
                  pkbls, skbls,
                  n, t, srs, my_id,
                  send, recv,
                  B_i)

await gg.run_graded_gather(node_communicator)
print("U =", gg.U)
print("T =", gg.T)
```
"""

from __future__ import annotations
import asyncio
import json
import logging
from typing import Dict, Optional

from .gather import YosoGather
from .yosorbc import YosoRBC

from beaver.utils.misc import wrap_send, subscribe_recv

# ---------------------------------------------------------------------
#  Hard‑coded VRF demo keys (identical to gather.py / yosorbc.py)
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

# Optional FFI (mirrors gather.py/yosorbc.py)
try:
    from ctypes import CDLL, c_char_p, c_void_p, string_at
    lib_bulletproof = CDLL("./libbulletproofs_amcl.so")
    lib_bulletproof.pyVrfProve.argtypes  = [c_char_p]
    lib_bulletproof.pyVrfProve.restype   = c_void_p
    lib_bulletproof.pyVrfVerify.argtypes = [c_char_p]
    lib_bulletproof.pyVrfVerify.restype  = c_void_p
    lib_bulletproof.pyFreeString.argtypes = [c_void_p]
    lib_bulletproof.pyFreeString.restype  = None
except OSError:
    lib_bulletproof = None
    from ctypes import string_at  # dmy to satisfy type checker

logger = logging.getLogger(__name__)


class GradedGather:
    """
    把 Fig. 18 拆成两步：

        1. 先内部生成 `YosoGather` 实例，跑完三轮 ΠGather 得到 U₃；
        2. 然后执行“一轮额外因果广播” → 计算 (U, T)。

    这样其他协议层只需要 import GradedGather 即可，不再直接触碰
    YosoGather 内部的私有方法。
    """

    # ------------------------------------------------------------------
    #  Construction
    # ------------------------------------------------------------------
    def __init__(self,
                 public_keys, private_key,
                 pkbls, skbls,
                 n: int, t: int, srs,
                 my_id: int,
                 send, recv,
                 B_i: bytes):
        # 把所有参数存起来，以便后续生成 RBC / Gather 实例
        self.public_keys = public_keys
        self.private_key = private_key
        self.pkbls = pkbls
        self.skbls = skbls
        self.n, self.t, self.srs = n, t, srs
        self.my_id = my_id
        self.send, self.recv = send, recv
        self.B_i = B_i

        self.vrf_sk_list = VRF_SK_LIST_DEC
        self.vrf_pk_list = VRF_PK_LIST

        # self._subscribe_task, self._subscribe_recv = subscribe_recv(recv)
        # def _recv(tag):                 # curry for convenience
        #     return self._subscribe_recv(tag)
        # self._recv = _recv

        # # Broadcast helper identical to yosorbc.py
        # def _mk_broadcast(tag: str):
        #     p2p_send = wrap_send(tag, send)        # closure over tag

        #     async def broadcast(payload: bytes):
        #         for dest in range(self.n):
        #             p2p_send(dest, payload)
        #     return broadcast
        # self._mk_broadcast = _mk_broadcast

        # 输出字段（初值）
        self.U: Dict[int, bytes] = {my_id: B_i}
        self.T: Dict[int, bytes] = {}

    
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
    
    # ------------------------------------------------------------------
    #  Convenience: reuse YosoGather._verify_vrf_proof via delegation
    # ------------------------------------------------------------------
    def _make_gather(self) -> YosoGather:
        """
        Helper to spawn an *internal* YosoGather object that
        shares the same (send, recv) channels.
        """
        return YosoGather(
            self.public_keys, self.private_key,
            self.pkbls, self.skbls,
            self.n, self.t, self.srs, self.my_id,
            self.send, self.recv,
            self.B_i
        )

    # ------------------------------------------------------------------
    #  VRF helpers – delegate to an internal YosoGather, created on‑demand
    # ------------------------------------------------------------------
    def _ensure_gather(self):
        """create self._gather once (so helper calls remain valid)"""
        if not hasattr(self, "_gather"):
            self._gather = self._make_gather()

    def _is_committee_member(self, label: bytes):
        self._ensure_gather()
        return self._gather._is_committee_member(label)

    def _verify_vrf_proof(self, label: bytes, proof: dict, sender_id: int):
        self._ensure_gather()
        return self._gather._verify_vrf_proof(label, proof, sender_id)

    # ------------------------------------------------------------------
    #  Main coroutine
    # ------------------------------------------------------------------
    async def run_graded_gather(self, node_communicator):
        """
        • 先跑 ΠGather  (内部调用 YosoGather.run_gather)；
        • 再做一次 RBC 扩散得到 (U, T)。

        参数
        ----
        node_communicator : 传递到 YosoGather 用于统计网络流量；
        gather_only       : 若设为 True，仅跑三轮 Gather 不做 graded‑round。
        """
        # --------------------------------------------------------------
        # (1)  先跑基本的 ΠGather
        # --------------------------------------------------------------
        g_inst = self._make_gather()
        self._gather = g_inst           # <- keep a handle for VRF helpers
        # 直接调用其 run_gather()，把 node_communicator 下传
        # await g_inst.run_gather(node_communicator)
        await g_inst._execute_gather()

        # copy 结果
        self.U = g_inst.U.copy()

        logger.info("[GGATHER] self.U: %s", self.U)

        # if gather_only:
        #     logger.info("[GGATHER] gather_only=True, skipping graded round")
        #     return

        # (2)  Invoke internal graded gather to compute U and T
        await g_inst._graded_gather_yosorbc()
        # copy union and intersection results
        self.U = g_inst.U.copy()
        self.T = g_inst.T.copy()
        logger.info("[GGATHER] finished – |U|=%d, |T|=%d", len(self.U), len(self.T))

        # … 在 await g_inst._graded_gather_yosorbc()，同步完 U、T 之后 …
        g_inst._subscribe_task.cancel()
        
        bytes_sent = node_communicator.bytes_sent
        for k,v in node_communicator.bytes_count.items():
            logger.info(f"[{self.my_id}] Bytes Sent: {k}:{v} which is {round((100*v)/bytes_sent,3)}%")
        logger.info(f"[{self.my_id}] Total bytes sent out aa: {bytes_sent}")

        # Gracefully shut down receive task and return so the process can exit
        return

    async def execute_graded_gather(self):
        """
        Execute ΠGather (3 rounds) then ΠGradedGather (causal broadcast) in one call.
        Uses the same node_communicator for traffic stats.
        """
        # 1) Run standard gather rounds
        g_inst = self._make_gather()
        self._gather = g_inst
        await g_inst._execute_gather()
        # copy interim U₃ result
        self.U = g_inst.U.copy()
        logger.info("[ExecGGATHER] U after gather: %s", self.U)

        # 2) Run graded gather broadcast
        await g_inst._graded_gather_yosorbc()
        # copy final U and T
        self.U = g_inst.U.copy()
        self.T = g_inst.T.copy()
        logger.info("[ExecGGATHER] finished – |U|=%d, |T|=%d",
                    len(self.U), len(self.T))

        # # 3) Cleanup subscription task
        # g_inst._subscribe_task.cancel()

       