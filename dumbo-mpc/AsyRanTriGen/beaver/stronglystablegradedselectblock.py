"""
ΠStronglyStableGradedSelectBlock  (Fig. 20) — 两轮 Upgrade 把 Weak 结果加固到 Strong。
"""

from __future__ import annotations
from .weakgradedselectblock import WeakGradedSelectBlock


class StronglyStableGradedSelectBlock(WeakGradedSelectBlock):
    """公开 run_strongly_stable()。需求：先跑 run_weak_select()。"""

    async def run_strongly_stable(self) -> None:
        if not hasattr(self, "C") or not hasattr(self, "g"):
            raise RuntimeError("先执行 run_weak_select() 取得 (C, g)")
        await self._strongly_stable_gradesel_yosorbc()