"""
ΠSelectBlock  (Fig. 21) — 顶层循环，直到产出 g=2 区块。
"""

from __future__ import annotations
from .stronglystablegradedselectblock import StronglyStableGradedSelectBlock


class SelectBlock(StronglyStableGradedSelectBlock):
    """
    调用:
        sb = SelectBlock(... 同 YosoGather 构造参数 ...)
        await sb.run_gather()          # 3-round Gather
        await sb.run_graded_gather()   # extra round
        await sb.run_weak_select()     # WeakGraded
        await sb.run_selectblock()     # ← 顶层循环，结束后
        final_blk  = sb.final_block
        final_round = sb.final_round
    """

    async def run_selectblock(self, max_rounds: int = 10) -> None:
        await self._select_block_yosorbc(max_rounds=max_rounds)