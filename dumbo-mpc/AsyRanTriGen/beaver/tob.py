# ── file: beaver/tob.py ──────────────────────────────────────────────
import asyncio
import json
import hashlib
import logging
from typing import Dict, List, Tuple, Optional
from ctypes import *

from beaver.gather import YosoGather        # 你的 ΠSelectBlock / ACS 打包器
from beaver.yosorbc import YosoRBC          # 你的单条可靠广播实现

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


class YosoTOB:
    """
    Top-level Total-Order Broadcast (ΠTOB) driver.

    • broadcast()  —— 对外 API，等价于 Fig 13-Broadcast message
    • wait()       —— 挂起直到本地账本 L_P 增长（Deliver 阶段）
    • set_wait_predicate(W) —— 运行时可更换等待谓词

    内部结构：
        – 每个输入 msg 都用 YosoRBC 广播，RBC-OUTPUT → PendingP
        – 一个后台任务 monitor_pending()：
              条件 |PendingP| ≥ max(W#, α) 且 W(L,Pending)=T 时，
              触发一次 propose_block()（调用 YosoGather）
        – gather 结束后由 deliver_block() 把消息写入本地账本。
    """
    # ———————————————————— 协议常数 ————————————————————
    W_MIN  = 1                    # 默认 W#_ℓ = 1（可热更新）

    def __init__(self,
                 public_keys, private_key, pkbls, skbls,
                 n, t, srs, my_id,
                 send, recv,
                 shared_subscribe=None,       # 复用顶层 dispatcher
                 predicate_name="default"):

        self.public_keys, self.private_key = public_keys, private_key
        self.pkbls, self.skbls = pkbls, skbls
        self.n, self.t, self.srs, self.my_id = n, t, srs, my_id
        self.send, self.recv = send, recv

        # 日志
        self.log = logging.getLogger("tob")
        self.predicate_name = predicate_name

        # 一个分发器即可把 (recv▶tag) 拆出多路
        if shared_subscribe is None:
            from beaver.utils.misc import subscribe_recv
            self._sub_task, self._sub_recv = subscribe_recv(recv)
            self._shared = (self._sub_task, self._sub_recv)
        else:
            self._shared = shared_subscribe
            self._sub_task, self._sub_recv = shared_subscribe

        # ——— Fig 13 状态 ————————————————————————————
        self.L: List[List[bytes]] = []         # 账本（区块链）
        self.c  = 0                            # Broadcast index
        self.b  = 0                            # Wait-predicate index
        self.WaitP: Dict[int, callable] = {}   # 记录每批次的 W^#
        self.coin0 = self.coin1 = 0            # 这里先留空

        self.Pending: List[Tuple[str, int, bytes]] = []   # (P',c,m)
        self._pending_lock = asyncio.Lock()

        # ——— 后台任务句柄 ————————————————————————
        self._bg_tasks: List[asyncio.Task] = []

        # Choose initial wait predicate based on protocol type
        if self.predicate_name == "PVmultiplication":
            self.WaitP[0] = self._predicate_PVmultiplication
        elif self.predicate_name == "B":
            self.WaitP[0] = self._predicate_B
        else:
            self.WaitP[0] = self._default_W_predicate

    # ==================================================================
    #  对外 API
    # ==================================================================
    async def start(self):
        """
        派生后台协程：1) monitor_pending  2) 每个 RBC 的 reactor
        在整个进程存活期间保持运行。
        """
        self._bg_tasks.append(asyncio.create_task(self._monitor_pending()))

    async def broadcast(self, m: bytes):
        """
        Fig 13 Broadcast message：为本地消息启动一个 RBC 实例。
        """
        tag_c = self.c
        self.c += 1
        prefix = f"BCAST_{self.my_id}_{tag_c}"

        rbc_sessions = {}
        for pid in range(self.n):
            prefix_i = f"BCAST_{pid}_{tag_c}"
            sess = YosoRBC(
                self.public_keys, self.private_key,
                self.pkbls, self.skbls,
                self.n, self.t, self.srs, self.my_id,
                self.send, self.recv,
                prefix=prefix_i,
                shared_subscribe=self._shared
            )
            rbc_sessions[pid] = sess
            # 后台运行 reactor
            asyncio.create_task(sess.reactor())

        # 仅本节点发起发送
        await rbc_sessions[self.my_id].sender(m)

        # 并行收集所有 dealer 的 RBC 输出
        for pid, sess in rbc_sessions.items():
            async def _collect(sess=sess, pid=pid):
                payload_bytes, _ = await sess.output_queue.get()
                logging.info("[COLLECT] node %d collected message at c=%d",
                             pid, tag_c)
                await self._schedule_message(pid, tag_c, payload_bytes)
            self._bg_tasks.append(asyncio.create_task(_collect()))

    async def wait(self):
        """异步阻塞直到本地账本新添区块；返回区块高度与区块内容。"""
        fut = asyncio.Future()

        async def waiter(old_len: int):
            while len(self.L) == old_len:
                await asyncio.sleep(0.05)
            fut.set_result((len(self.L) - 1, self.L[-1]))

        asyncio.create_task(waiter(len(self.L)))
        return await fut                # (height, block_messages)

    def set_wait_predicate(self, pred_callable):
        """
        外部动态更新等待谓词 (wait, W)。下一批次生效。
        W 应当满足接口：  W(L_P, PendingP) -> bool
        同时提供 W# = 最小需要满足的引用数，可通过属性 `.min_size`
        """
        self.b += 1
        self.WaitP[self.b] = pred_callable

    # ==================================================================
    #  内部阶段实现
    # ==================================================================
    async def _schedule_message(self, Pprim, c_idx, payload: bytes):
        """
        Fig 13 Schedule message (IIRB 输出) —— 加入 Pending_P。
        """
        logging.info("[SCHEDULE] node %d scheduled message at c=%d",
                     self.my_id, c_idx)
        async with self._pending_lock:
            self.Pending.append((Pprim, c_idx, payload))

    async def _monitor_pending(self):
        """
        不断检查 Pending_P 是否满足“触发提议”的条件。
        满足则调用 propose_block()。
        """
        while True:
            await asyncio.sleep(0.02)
            async with self._pending_lock:
                # Select the wait predicate for the upcoming round, defaulting to the initial predicate
                Wf = self.WaitP.get(len(self.L) + 1, self.WaitP.get(0, self._default_W_predicate))
                # self.log.info("[MONITOR] Checking predicate %s with pending size %d",
                #               (Wf.__name__ if (Wf := self.WaitP.get(len(self.L) + 1, self._default_W_predicate)) else "unknown"),
                #               len(self.Pending))
                # Trigger only when ≥2t+1 entries are pending
                need = 2 * self.t + 1
                if len(self.Pending) < need:
                    continue
                try:
                    selected = Wf(self.L, self.Pending)
                except Exception as e:
                    self.log.error("[MONITOR] wait predicate error: %s", e)
                    continue
                # Expect selected to be a list of entries passing the predicate
                if not selected or len(selected) < need:
                    continue
                # Remove the chosen entries from Pending
                to_use = selected[:need]
                for entry in to_use:
                    self.Pending.remove(entry)
 

            # 一旦跳出锁，异步开始 propose_block
            asyncio.create_task(self._propose_block(to_use, Wf))

    async def _propose_block(self,
                             selected_msgs: List[Tuple[str, int, bytes]],
                             Wf):
        """
        Fig 13 Propose Block —— 打包区块并调用 ΠACS (YosoGather)
        """
        # ------ 1) 构造 B = 至多 W# 条满足谓词的引用 -------------
        need = 2 * self.t + 1          # 和 _monitor_pending 保持一致
        B_refs = selected_msgs[:need]

        # ------ 3) B'' 只包含上一次输出轮数 r_{|L|} -------------
        last_round = len(self.L)      # 简化：用高度当作 round
        B_pprime   = [("LAST", last_round)]

        # ------ 4) 串接并编码为 bytes  -----------------------------
        def encode_entry(entry):
            if entry[0] == "LAST":
                return json.dumps({"LAST": entry[1]}).encode()
            Pprim, c_idx, payload = entry
            meta = {"P": Pprim, "c": c_idx}
            return json.dumps(meta).encode() + b"|" + payload

        payload_block = [encode_entry(e) for e in (B_refs + B_pprime)]
        block_bytes   = b"||".join(payload_block)

        # ------ 5) 调用 ΠACS（YosoGather）达成一致 ----------------
        gather = YosoGather(
            self.public_keys, self.private_key,
            self.pkbls, self.skbls,
            self.n, self.t, self.srs, self.my_id,
            self.send, self.recv,
            block_bytes,
            shared_subscribe=self._shared
        )

        await gather.run_gather(node_communicator=None)   # 若已有 wrapper，可传
        await self._deliver_block(gather.final_block)

    async def _deliver_block(self, block_bytes: bytes):
        """
        Fig 13 Deliver —— 所有人对同一块达成一致后追加到账本。
        """
        # 这里把 block_bytes 简单拆分成消息列表
        parts = block_bytes.split(b"||")
        msgs  = []
        for p in parts:
            if p.startswith(b'{"LAST"'):
                continue
            meta_json, payload = p.split(b"|", 1)
            meta = json.loads(meta_json.decode())
            msgs.append(payload)       # 或保留 meta

        self.L.append(msgs)
        self.log.info("[DELIVER] node %d appended block %d (%d msgs)",
                      self.my_id, len(self.L) - 1, len(msgs))

    # ------------------------------------------------------------------
    #  Public helper: 停止后台任务，防止事件循环关闭时报 Pending
    # ------------------------------------------------------------------
    async def stop(self):
        """Cancel monitor-pending 与 subscribe-dispatcher 等后台协程。"""
        for t in list(self._bg_tasks):
            t.cancel()
        if hasattr(self, "_sub_task"):
            self._sub_task.cancel()

    # 为兼容旧代码保留别名
    kill = stop

    def get_last_block(self) -> Optional[List[bytes]]:
        """Return the most recently delivered block as a list of message bytes, or None if no blocks yet."""
        return self.L[-1] if self.L else None

    def get_block(self, height: int) -> List[bytes]:
        """Return the block at the given height index."""
        if 0 <= height < len(self.L):
            return self.L[height]
        raise IndexError(f"Block height {height} out of range")

    # ==================================================================
    #  默认等待谓词（可被 set_wait_predicate 替换），这里是我们 PVtransfer 的谓词
    # ==================================================================
    def _default_W_predicate(self, L: List, P: List) -> List[Tuple[str, int, bytes]]:
        """
        新谓词：对 Pending 里的每个 payload 用 PVTransferPayload.from_bytes 检查结构合法性，并验证每个 EncResult 的证明。
        """
        import logging
        logging.info("[W-PRED] _default_W_predicate called with %d pending entries", len(P))
        from beaver.pvtransfer import PVTransferPayload

        thr = 2 * self.t + 1                   # 需要的条目数
        logging.info("[W-PRED] Threshold for valid entries: %d", thr)
        valid: List[Tuple[str, int, bytes]] = []
        bad_idx: List[int] = []               # 记录要删除的索引（倒序遍历安全）

        # ——— 逆序遍历 P，验证通过就放进 valid，失败就记 idx —— 
        for idx in range(len(P) - 1, -1, -1):
            entry = P[idx]
        # for entry in P:
            try:
                # logging.info("[W-PRED] Processing entry, entry: %s", entry)
                _, _, payload = entry
                pv_obj = PVTransferPayload.from_bytes(payload)
                # logging.info("[W-PRED] Parsed PVTransferPayload: %s", pv_obj)
                # --- 验证每个 EncResult 的证明 ---
                from Crypto.Util.number import long_to_bytes
                # 1) 解码 SRS 中的生成元
                srs_dict = json.loads(self.srs["Pk"].decode("utf-8"))
                gx_dec = int(srs_dict["G1_g"][0]["X"]); gy_dec = int(srs_dict["G1_g"][0]["Y"])
                hx_dec = int(srs_dict["G1_h"][0]["X"]); hy_dec = int(srs_dict["G1_h"][0]["Y"])
                uncompressed_g_hex = (b"\x04" + long_to_bytes(gx_dec,48) + long_to_bytes(gy_dec,48)).hex()
                uncompressed_h_hex = (b"\x04" + long_to_bytes(hx_dec,48) + long_to_bytes(hy_dec,48)).hex()

                # --- Bulletproof Full proof 验证 ---
                all_bp_ok = True
                for node_idx, enc in enumerate(pv_obj.enc_results):
                    # 构造验证载荷
                    payload_verify = {
                        "g": uncompressed_g_hex,
                        "h": uncompressed_h_hex,
                        "pk": enc.pk if isinstance(enc.pk, str) else (b"\x04" + long_to_bytes(int(enc.pk["X"]),48) + long_to_bytes(int(enc.pk["Y"]),48)).hex(),
                        "C1": enc.C1,
                        "C2": enc.C2,
                        "W":  enc.W,
                        "proof": enc.proof
                    }
                    json_input_verify = json.dumps(payload_verify).encode("utf-8")
                    ptr_verify = lib_bulletproof.pyVerifyFull(json_input_verify)
                    # raw = string_at(ptr_verify).decode("utf-8")
                    ok = json.loads(string_at(ptr_verify).decode())["verified"]
                    lib_bulletproof.pyFreeString(ptr_verify)
                    logging.info("[W-PRED] Bulletproof verify result for node %d: %s", node_idx, ok)
                    if not ok:
                        all_bp_ok = False
                        break
                if not all_bp_ok:
                    raise ValueError("bulletproof failed")

                # ---- KZG 聚合验证: 先解析 commitment 字段 ----
                try:
                    commitment_raw = pv_obj.commitment
                    # commitment_raw 在 JSON 过程中可能被二次转义 => 字符串里再嵌字符串
                    if isinstance(commitment_raw, str):
                        commit_obj = json.loads(commitment_raw)       # 第一次 loads
                        if isinstance(commit_obj, str):
                            commit_obj = json.loads(commit_obj)       # 再解一层
                        commitment_list = commit_obj
                    else:
                        commitment_list = commitment_raw              # 已经是 list
                except Exception as e_parse:
                    logging.warning("[W-PRED] commitment parse error: %s", e_parse)
                    continue

                # 紧凑编码为 bytes，供 pyDeriveChallenge 使用
                serialized_commitment = json.dumps(
                    commitment_list, separators=(",", ":")
                ).encode("utf-8")
                # logging.info("[W-PRED] Serialized commitment: %s", serialized_commitment)
                challenge = lib.pyDeriveChallenge(serialized_commitment)
                # logging.info("[W-PRED] Derived challenge: %s", challenge)
                vk_arg = self.srs["Vk"]

                # 1) 验证 agg_secrets_commitment 与 agg_proof_at_zero
                ok_combined = lib.pyPubAggVerifyEvalCombined(
                    vk_arg,
                    serialized_commitment,
                    pv_obj.agg_secrets_commitment.encode("utf-8"),
                    pv_obj.agg_proof_at_zero.encode("utf-8"),
                    challenge,
                    0
                )
                logging.info("[W-PRED] Combined KZG verify result: %s", ok_combined)
                if not ok_combined:
                    raise ValueError("KZG combined fail")

                # 2) 验证每个节点的聚合 W 证明
                all_valid_kzg = True
                from Crypto.Util.number import long_to_bytes as _unused_long_to_bytes  # ensure imported
                # helper to parse uncompressed G1 hex to dict
                def _parse_uncompressed_G1(hex_str: str) -> dict:
                    data = bytes.fromhex(hex_str)
                    if data[0] != 0x04:
                        raise ValueError("Invalid uncompressed G1 prefix")
                    x = int.from_bytes(data[1:49], byteorder="big")
                    y = int.from_bytes(data[49:97], byteorder="big")
                    return {"X": str(x), "Y": str(y)}
                for idx, enc in enumerate(pv_obj.enc_results):
                    # reconstruct per-node aggregated W commitment via KZG
                    structured_W_list = [{"H": _parse_uncompressed_G1(w)} for w in enc.W]
                    serialized_structured_W = json.dumps(structured_W_list).encode("utf-8")
                    ptr_node = lib.pyAggProveEvalZero(serialized_structured_W, challenge)
                    node_agg = json.dumps(json.loads(ptr_node.decode("utf-8"))["aggH"])
                    aggW_node = node_agg.encode("utf-8")

                    # use aggregated_proof_list as per-node proofs (encoded as utf-8)
                    point_idx = idx + 1
                    ok_node = lib.pyPubAggVerifyEvalCombined(
                        vk_arg,
                        serialized_commitment,
                        aggW_node,
                        pv_obj.aggregated_proof_list[idx].encode("utf-8"),
                        challenge,
                        point_idx
                    )
                    logging.info("[W-PRED] KZG verify result for node %d: %s", idx, ok_node)
                    if not ok_node:
                        all_valid_kzg = False
                        break
                if not all_valid_kzg:
                    raise ValueError("KZG combined fail")

                # logging.info("[W-PRED] Proofs verified for entry: %s", pv_obj)
                # —— 通过所有检查 —— 
                valid.append(entry)

            except Exception as e:
                logging.warning("[W-PRED] drop invalid entry: %s", e)
                bad_idx.append(idx)
        # return len(P) >= 3
        # —— 删除所有验证失败的项（倒序索引已保证安全） —— 
        for i in bad_idx:
            P.pop(i)

        # —— 返回结果给 monitor —— 
        if len(valid) >= thr:
            logging.info("[W-PRED] Returning %d valid entries", len(valid))
            return valid[:thr]          # 够 2t+1，挑前 thr 条
        return []                       # 还不够，让 monitor 再等等

    def _predicate_PVmultiplication(self, L: List, P: List) -> List[Tuple[str, int, bytes]]:
        """
        Protocol PVmultiplication specific wait predicate.
        """

        import logging
        logging.info("[W-PRED] _default_W_predicate called with %d pending entries", len(P))
        from beaver.pvmultiplication import PVMultiplicationPayload

        thr = 2 * self.t + 1                   # 需要的条目数
        logging.info("[W-PRED] Threshold for valid entries: %d", thr)
        valid: List[Tuple[str, int, bytes]] = []
        bad_idx: List[int] = []               # 记录要删除的索引（倒序遍历安全）

        # ——— 逆序遍历 P，验证通过就放进 valid，失败就记 idx —— 
        for idx in range(len(P) - 1, -1, -1):
            entry = P[idx]
        # for entry in P:
            try:
                # logging.info("[W-PRED] Processing entry, entry: %s", entry)
                _, _, payload = entry
                pv_obj = PVMultiplicationPayload.from_bytes(payload)
                # logging.info("[W-PRED] Parsed PVTransferPayload: %s", pv_obj)
                # --- 验证每个 EncResult 的证明 ---
                from Crypto.Util.number import long_to_bytes
                # 1) 解码 SRS 中的生成元
                srs_dict = json.loads(self.srs["Pk"].decode("utf-8"))
                gx_dec = int(srs_dict["G1_g"][0]["X"]); gy_dec = int(srs_dict["G1_g"][0]["Y"])
                hx_dec = int(srs_dict["G1_h"][0]["X"]); hy_dec = int(srs_dict["G1_h"][0]["Y"])
                uncompressed_g_hex = (b"\x04" + long_to_bytes(gx_dec,48) + long_to_bytes(gy_dec,48)).hex()
                uncompressed_h_hex = (b"\x04" + long_to_bytes(hx_dec,48) + long_to_bytes(hy_dec,48)).hex()

                # --- Bulletproof Full proof 验证 ---
                all_bp_ok = True
                for node_idx, enc in enumerate(pv_obj.enc_results):
                    # 构造验证载荷
                    payload_verify = {
                        "g": uncompressed_g_hex,
                        "h": uncompressed_h_hex,
                        "pk": enc.pk if isinstance(enc.pk, str) else (b"\x04" + long_to_bytes(int(enc.pk["X"]),48) + long_to_bytes(int(enc.pk["Y"]),48)).hex(),
                        "C1": enc.C1,
                        "C2": enc.C2,
                        "W":  enc.W,
                        "proof": enc.proof
                    }
                    json_input_verify = json.dumps(payload_verify).encode("utf-8")
                    ptr_verify = lib_bulletproof.pyVerifyFull(json_input_verify)
                    # raw = string_at(ptr_verify).decode("utf-8")
                    ok = json.loads(string_at(ptr_verify).decode())["verified"]
                    lib_bulletproof.pyFreeString(ptr_verify)
                    logging.info("[W-PRED] Bulletproof verify result for node %d: %s", node_idx, ok)
                    if not ok:
                        all_bp_ok = False
                        break
                if not all_bp_ok:
                    raise ValueError("bulletproof failed")

                # ---- KZG 聚合验证: 先解析 commitment 字段 ----
                try:
                    commitment_raw = pv_obj.commitment
                    # commitment_raw 在 JSON 过程中可能被二次转义 => 字符串里再嵌字符串
                    if isinstance(commitment_raw, str):
                        commit_obj = json.loads(commitment_raw)       # 第一次 loads
                        if isinstance(commit_obj, str):
                            commit_obj = json.loads(commit_obj)       # 再解一层
                        commitment_list = commit_obj
                    else:
                        commitment_list = commitment_raw              # 已经是 list
                except Exception as e_parse:
                    logging.warning("[W-PRED] commitment parse error: %s", e_parse)
                    continue

                # 紧凑编码为 bytes，供 pyDeriveChallenge 使用
                serialized_commitment = json.dumps(
                    commitment_list, separators=(",", ":")
                ).encode("utf-8")
                # logging.info("[W-PRED] Serialized commitment: %s", serialized_commitment)
                challenge = lib.pyDeriveChallenge(serialized_commitment)
                # logging.info("[W-PRED] Derived challenge: %s", challenge)
                vk_arg = self.srs["Vk"]

                # 1) 验证 agg_secrets_commitment 与 agg_proof_at_zero
                ok_combined = lib.pyPubAggVerifyEvalCombined(
                    vk_arg,
                    serialized_commitment,
                    pv_obj.agg_secrets_commitment.encode("utf-8"),
                    pv_obj.agg_proof_at_zero.encode("utf-8"),
                    challenge,
                    0
                )
                logging.info("[W-PRED] Combined KZG verify result: %s", ok_combined)
                if not ok_combined:
                    raise ValueError("KZG combined fail")

                # 2) 验证每个节点的聚合 W 证明
                all_valid_kzg = True
                from Crypto.Util.number import long_to_bytes as _unused_long_to_bytes  # ensure imported
                # helper to parse uncompressed G1 hex to dict
                def _parse_uncompressed_G1(hex_str: str) -> dict:
                    data = bytes.fromhex(hex_str)
                    if data[0] != 0x04:
                        raise ValueError("Invalid uncompressed G1 prefix")
                    x = int.from_bytes(data[1:49], byteorder="big")
                    y = int.from_bytes(data[49:97], byteorder="big")
                    return {"X": str(x), "Y": str(y)}
                for idx, enc in enumerate(pv_obj.enc_results):
                    # reconstruct per-node aggregated W commitment via KZG
                    structured_W_list = [{"H": _parse_uncompressed_G1(w)} for w in enc.W]
                    serialized_structured_W = json.dumps(structured_W_list).encode("utf-8")
                    ptr_node = lib.pyAggProveEvalZero(serialized_structured_W, challenge)
                    node_agg = json.dumps(json.loads(ptr_node.decode("utf-8"))["aggH"])
                    aggW_node = node_agg.encode("utf-8")

                    # use aggregated_proof_list as per-node proofs (encoded as utf-8)
                    point_idx = idx + 1
                    ok_node = lib.pyPubAggVerifyEvalCombined(
                        vk_arg,
                        serialized_commitment,
                        aggW_node,
                        pv_obj.aggregated_proof_list[idx].encode("utf-8"),
                        challenge,
                        point_idx
                    )
                    logging.info("[W-PRED] KZG verify result for node %d: %s", idx, ok_node)
                    if not ok_node:
                        all_valid_kzg = False
                        break
                if not all_valid_kzg:
                    raise ValueError("KZG combined fail")

                # logging.info("[W-PRED] Proofs verified for entry: %s", pv_obj)
                # —— 通过所有检查 —— 
                valid.append(entry)

            except Exception as e:
                logging.warning("[W-PRED] drop invalid entry: %s", e)
                bad_idx.append(idx)
        # return len(P) >= 3
        # —— 删除所有验证失败的项（倒序索引已保证安全） —— 
        for i in bad_idx:
            P.pop(i)

        # —— 返回结果给 monitor —— 
        if len(valid) >= thr:
            logging.info("[W-PRED] Returning %d valid entries", len(valid))
            return valid[:thr]          # 够 2t+1，挑前 thr 条
        return []                       # 还不够，让 monitor 再等等

    def _predicate_B(self, L: List, P: List) -> List[Tuple[str, int, bytes]]:
        """
        Protocol B specific wait predicate.
        """
        # TODO: implement logic for protocol B
        return self._default_W_predicate(L, P)