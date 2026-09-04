"""Stage-5 adapter for independently tagged g- and h-based all-powers runs.

The locked upstream ``ALL_POWERS`` implementation is already generic in its
G1 base, but hard-codes an inner ``AP`` tag.  This adapter leaves that source
untouched and places each instance below a distinct outer route, producing
``AP_G/AP`` and ``AP_H/AP`` on the wire.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Sequence, Tuple

from ..config import SetupParams
from .bootstrap import activate_upstream


activate_upstream()

from adkg.adkg import ADKG  # noqa: E402
from adkg.all_powers import ALL_POWERS  # noqa: E402


AP_G_TAG = "AP_G"
AP_H_TAG = "AP_H"


def _new_all_powers(instance: Any, base: Any, outer_tag: str) -> Any:
    send = instance.get_send(outer_tag)
    recv = instance.subscribe_recv(outer_tag)
    return ALL_POWERS(
        base,
        instance.g2,
        instance.n,
        instance.t,
        instance.logq,
        instance.my_id,
        instance.omega2,
        send,
        recv,
        instance.curve_params,
    )


class DualChainADKG(ADKG):
    """Run the upstream g-chain under the explicit ``AP_G`` route."""

    async def run_adkg(self, start_time):
        self.stage5_started = time.perf_counter()
        return await super().run_adkg(start_time)

    async def squaring(self, t_share, t_pk, t_commits, params):
        self.setup_elapsed_seconds = time.perf_counter() - self.stage5_started
        started = time.perf_counter()
        result = await super().squaring(t_share, t_pk, t_commits, params)
        self.squaring_elapsed_seconds = time.perf_counter() - started
        return result

    async def g2_powers(self, t_shares, t_commits):
        started = time.perf_counter()
        result = await super().g2_powers(t_shares, t_commits)
        self.g2_powers_elapsed_seconds = time.perf_counter() - started
        return result

    async def all_powers(self, t_shares, t_commits, t_powers, g2powers):
        self.ap_g = _new_all_powers(self, self.g, AP_G_TAG)
        # Preserve upstream attribute names for its existing lifecycle helpers.
        self.ap = self.ap_g
        started = time.perf_counter()
        self.ap_g_task = asyncio.create_task(
            self.ap_g.powers(t_shares, t_commits, t_powers, g2powers)
        )
        self.ap_task = self.ap_g_task
        powers = await self.ap_g_task
        self.ap_g_elapsed_seconds = time.perf_counter() - started
        return powers


async def run_h_all_powers_party(
    *,
    instance: Any,
    raw_output: Sequence[Any],
    t_commits_h: Sequence[Sequence[Any]],
    base_h: Any,
    params: SetupParams,
) -> Tuple[Any, ...]:
    power_shares = tuple(
        raw_output[5][index] for index in range(params.log_q + 1)
    )
    g2_powers = tuple(instance.gp_task.result())
    h_powers_of_two = tuple(row[0] for row in t_commits_h)

    instance.ap_h = _new_all_powers(instance, base_h, AP_H_TAG)
    instance.ap_h_task = asyncio.create_task(
        instance.ap_h.powers(
            power_shares,
            t_commits_h,
            h_powers_of_two,
            g2_powers,
        )
    )
    return tuple(await instance.ap_h_task)


async def run_h_all_powers_phase(
    *,
    instances: Sequence[Any],
    raw_outputs: Sequence[Sequence[Any]],
    t_commits_h_views: Sequence[Sequence[Sequence[Any]]],
    base_h: Any,
    params: SetupParams,
) -> Tuple[Tuple[Any, ...], ...]:
    """Sequentially follow AP_G with an all-party ``AP_H`` execution."""

    if (
        len(instances) != params.n
        or len(raw_outputs) != params.n
        or len(t_commits_h_views) != params.n
    ):
        raise ValueError("AP_H requires one instance, output, and view per party")

    tasks = [
        asyncio.create_task(
            run_h_all_powers_party(
                instance=instance,
                raw_output=raw_output,
                t_commits_h=t_commits_h,
                base_h=base_h,
                params=params,
            )
        )
        for instance, raw_output, t_commits_h in zip(
            instances, raw_outputs, t_commits_h_views
        )
    ]
    try:
        return tuple(await asyncio.gather(*tasks))
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
