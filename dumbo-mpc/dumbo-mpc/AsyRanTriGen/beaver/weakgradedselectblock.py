"""
ΠWeakGradedSelectBlock  (Fig. 19) — 在 GradedGather 基础上运行一次弱分级选块。
"""

from __future__ import annotations
from .gradedgather import GradedGather


class WeakGradedSelectBlock(GradedGather):
    """公开 run_weak_select()。需求：先跑完 run_graded_gather()。"""

    async def run_weak_select(self) -> None:
        if not getattr(self, "U", None):
            raise RuntimeError("先调用 run_graded_gather() 初始化 U、T")
        await self._weak_gradesel_yosorbc()