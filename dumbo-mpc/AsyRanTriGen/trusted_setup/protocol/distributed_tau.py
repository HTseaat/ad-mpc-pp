"""All-honest local execution of the upstream single-chain Powers-of-Tau path.

This adapter does not modify the locked upstream source. It invokes upstream
ADKG, random double sharing, squaring, G2 powers, and all-powers, then exposes
the G2 result that upstream computes but omits from its public output.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Iterable, List, Sequence, Tuple

from ..config import SetupParams
from .base_link import (
    BaseLinkMessage,
    public_bases,
    run_base_link_party,
    run_base_link_phase,
)
from .bootstrap import activate_upstream
from .dual_chain import (
    DualChainADKG,
    run_h_all_powers_party,
    run_h_all_powers_phase,
)


activate_upstream()

from adkg.poly_commit_hybrid import PolyCommitHybrid  # noqa: E402
from adkg.utils.poly_misc import get_omega  # noqa: E402
from pypairing import (  # noqa: E402
    G1,
    ZR,
    blsfft,
    blsmultiexp as multiexp,
    dotprod,
)
from .instrumentation import MeasuredRouter

# Keep the machine-readable CLI output clean. Upstream configures the root
# logger at import time and otherwise emits one line per party and phase.
logging.getLogger().setLevel(logging.WARNING)


@dataclass(frozen=True)
class PartyOutput:
    party_id: int
    alpha_share: Any
    g_chain: Tuple[Any, ...]
    h_chain: Tuple[Any, ...]
    powers_of_two_g1: Tuple[Any, ...]
    t_commits_g: Tuple[Tuple[Any, ...], ...]
    powers_of_two_h1: Tuple[Any, ...]
    t_commits_h: Tuple[Tuple[Any, ...], ...]
    base_link_messages: Tuple[BaseLinkMessage, ...]
    powers_of_two_g2: Tuple[Any, ...]
    g2: Any
    alpha_g2: Any


@dataclass(frozen=True)
class LocalSetupResult:
    params: SetupParams
    parties: Tuple[PartyOutput, ...]
    g: Any
    h: Any
    g2: Any
    elapsed_seconds: float
    setup_elapsed_seconds: float
    squaring_elapsed_seconds: float
    g2_powers_elapsed_seconds: float
    base_link_elapsed_seconds: float
    g_all_powers_elapsed_seconds: float
    h_all_powers_elapsed_seconds: float
    sent_bytes_per_party: Tuple[int, ...]
    sent_messages_per_party: Tuple[int, ...]
    sent_bytes_by_tag: Tuple[dict[str, int], ...]
    pending_protocol_tasks: int


@dataclass(frozen=True)
class DistributedPartyResult:
    """One party's output and local timings from a real network execution."""

    params: SetupParams
    parties: Tuple[PartyOutput, ...]
    g: Any
    h: Any
    g2: Any
    elapsed_seconds: float
    setup_elapsed_seconds: float
    squaring_elapsed_seconds: float
    g2_powers_elapsed_seconds: float
    base_link_elapsed_seconds: float
    g_all_powers_elapsed_seconds: float
    h_all_powers_elapsed_seconds: float
    pending_protocol_tasks: int


def _matrix_multiply(left: Sequence[Sequence[Any]], right: Sequence[Sequence[Any]]):
    rows = len(left)
    inner = len(right)
    columns = len(right[0])
    return [
        [
            sum(
                (left[row][idx] * right[idx][column] for idx in range(inner)),
                ZR(0),
            )
            for column in range(columns)
        ]
        for row in range(rows)
    ]


def _sharing_matrices(t: int, n: int):
    degree = 2 * t
    coefficient_low = [
        [ZR(row + 1) ** exponent for exponent in range(t + 1)]
        for row in range(n)
    ]
    coefficient_high = [
        [ZR(row + 1) ** exponent for exponent in range(t + 1, degree + 1)]
        for row in range(n)
    ]
    hyper_low = [
        [ZR(column + 1) ** exponent for column in range(n)]
        for exponent in range(t + 1)
    ]
    hyper_high = [
        [ZR(column + 1) ** exponent for column in range(n)]
        for exponent in range(degree - t)
    ]
    return (
        _matrix_multiply(coefficient_low, hyper_low),
        _matrix_multiply(coefficient_high, hyper_high),
    )


def _owned_tasks(instance: Any) -> set:
    tasks = set()
    for name in (
        "subscribe_recv_task",
        "acss_task",
        "rds_task",
        "sq_task",
        "gp_task",
        "ap_task",
        "ap_g_task",
        "ap_h_task",
    ):
        task = getattr(instance, name, None)
        if isinstance(task, asyncio.Task):
            tasks.add(task)
    for task in getattr(instance, "acss_tasks", ()):
        if isinstance(task, asyncio.Task):
            tasks.add(task)
    for task in getattr(instance, "tasks", ()):
        if isinstance(task, asyncio.Task):
            tasks.add(task)
    tagvars = getattr(instance, "tagvars", {})
    for values in tagvars.values():
        for task in values.get("tasks", ()):
            if isinstance(task, asyncio.Task):
                tasks.add(task)
    return tasks


async def _shutdown(instances: Iterable[Any], root_tasks: Iterable[asyncio.Task]) -> int:
    components = []
    for instance in instances:
        components.append(instance)
        for name in ("acss", "rds", "sq", "gp", "ap", "ap_g", "ap_h"):
            component = getattr(instance, name, None)
            if component is not None:
                components.append(component)

    tasks = set(root_tasks)
    for component in components:
        tasks.update(_owned_tasks(component))
        kill = getattr(component, "kill", None)
        if callable(kill):
            try:
                kill()
            except Exception:
                # Cleanup must still cancel every task even if an upstream kill
                # method assumes an attribute that was never initialized.
                pass

    for task in tasks:
        if not task.done():
            task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.sleep(0)
    return sum(not task.done() for task in tasks)


async def run_local_setup(
    params: SetupParams,
    *,
    timeout_seconds: float = 180.0,
) -> LocalSetupResult:
    """Run all ``n`` honest parties over the upstream in-memory async router."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    # g and g2 are the binding's standard BLS12-381 generators.  h is derived
    # from a fixed public domain without publishing a known discrete-log link.
    g, h, g2 = public_bases()
    private_keys = [
        ZR.hash(f"{params.run_id}:pki:{party_id}".encode("utf-8"))
        for party_id in range(params.n)
    ]
    public_keys = [g ** private_key for private_key in private_keys]

    router = MeasuredRouter(params.n)
    omega2 = get_omega(ZR, 2 * params.n, 1729)
    commitment = PolyCommitHybrid(g, h, ZR, multiexp)
    matrices = _sharing_matrices(params.t, params.n)
    curve_params = (ZR, G1, multiexp, dotprod, blsfft)

    instances: List[Any] = []
    protocol_tasks: List[asyncio.Task] = []
    started = time.perf_counter()
    raw_outputs = None
    base_link_views = None
    h_chains = None
    base_link_elapsed = 0.0
    h_all_powers_elapsed = 0.0
    pending = -1
    try:
        for party_id in range(params.n):
            instance = DualChainADKG(
                public_keys,
                private_keys[party_id],
                g,
                h,
                g2,
                params.n,
                params.t,
                params.log_q,
                party_id,
                omega2,
                router.sends[party_id],
                router.recvs[party_id],
                commitment,
                curve_params,
                matrices,
            )
            instances.append(instance)
            protocol_tasks.append(
                asyncio.create_task(instance.run_adkg(time.time()))
            )

        receive_all = asyncio.gather(
            *(instance.output_queue.get() for instance in instances)
        )
        raw_outputs = await asyncio.wait_for(receive_all, timeout=timeout_seconds)
        await asyncio.gather(*protocol_tasks)

        base_link_started = time.perf_counter()
        base_link_views = await asyncio.wait_for(
            run_base_link_phase(
                instances=instances,
                raw_outputs=raw_outputs,
                params=params,
                g=g,
                h=h,
            ),
            timeout=timeout_seconds,
        )
        base_link_elapsed = time.perf_counter() - base_link_started

        h_all_powers_started = time.perf_counter()
        h_chains = await asyncio.wait_for(
            run_h_all_powers_phase(
                instances=instances,
                raw_outputs=raw_outputs,
                t_commits_h_views=tuple(
                    view.t_commits_h for view in base_link_views
                ),
                base_h=h,
                params=params,
            ),
            timeout=timeout_seconds,
        )
        h_all_powers_elapsed = time.perf_counter() - h_all_powers_started

        party_outputs = []
        for party_id, (instance, raw_output, base_link_view, h_chain) in enumerate(
            zip(instances, raw_outputs, base_link_views, h_chains)
        ):
            # Upstream output layout:
            # values[1], mks, alpha_share, alpha_g, params, pt_shares,
            # pt_commits, all_g_powers. G2 powers are computed by gp_task but
            # omitted; export them here without recomputing them centrally.
            alpha_share = raw_output[2]
            powers_of_two_g1 = tuple(
                raw_output[6][idx][0] for idx in range(params.log_q + 1)
            )
            t_commits_g = tuple(
                tuple(raw_output[6][idx]) for idx in range(params.log_q + 1)
            )
            g_chain = tuple(raw_output[7])
            g2_powers = tuple(instance.gp_task.result())
            party_outputs.append(
                PartyOutput(
                    party_id=party_id,
                    alpha_share=alpha_share,
                    g_chain=g_chain,
                    h_chain=h_chain,
                    powers_of_two_g1=powers_of_two_g1,
                    t_commits_g=t_commits_g,
                    powers_of_two_h1=tuple(
                        row[0] for row in base_link_view.t_commits_h
                    ),
                    t_commits_h=base_link_view.t_commits_h,
                    base_link_messages=base_link_view.messages,
                    powers_of_two_g2=g2_powers,
                    g2=g2,
                    alpha_g2=g2_powers[0],
                )
            )
    finally:
        pending = await _shutdown(instances, protocol_tasks)

    if raw_outputs is None or base_link_views is None or h_chains is None:
        raise RuntimeError("the setup protocol did not produce outputs")
    elapsed = time.perf_counter() - started
    logging.getLogger(__name__).debug("local setup completed in %.6fs", elapsed)
    return LocalSetupResult(
        params=params,
        parties=tuple(party_outputs),
        g=g,
        h=h,
        g2=g2,
        elapsed_seconds=elapsed,
        setup_elapsed_seconds=max(
            instance.setup_elapsed_seconds for instance in instances
        ),
        squaring_elapsed_seconds=max(
            instance.squaring_elapsed_seconds for instance in instances
        ),
        g2_powers_elapsed_seconds=max(
            instance.g2_powers_elapsed_seconds for instance in instances
        ),
        base_link_elapsed_seconds=base_link_elapsed,
        g_all_powers_elapsed_seconds=max(
            instance.ap_g_elapsed_seconds for instance in instances
        ),
        h_all_powers_elapsed_seconds=h_all_powers_elapsed,
        sent_bytes_per_party=tuple(router.sent_bytes),
        sent_messages_per_party=tuple(router.sent_messages),
        sent_bytes_by_tag=router.bytes_by_tag(),
        pending_protocol_tasks=pending,
    )


async def run_distributed_party_setup(
    params: SetupParams,
    *,
    party_id: int,
    send: Any,
    recv: Any,
    timeout_seconds: float = 180.0,
) -> DistributedPartyResult:
    """Run exactly one setup party over a caller-provided network transport."""

    if type(party_id) is not int or not 0 <= party_id < params.n:
        raise ValueError("party_id must index the setup committee")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    g, h, g2 = public_bases()
    # This deterministic experiment PKI preserves the existing all-honest
    # benchmark semantics.  It is not the deferred production key-provisioning
    # and state-release hardening from stage 7.
    private_keys = [
        ZR.hash(f"{params.run_id}:pki:{index}".encode("utf-8"))
        for index in range(params.n)
    ]
    public_keys = [g ** private_key for private_key in private_keys]
    omega2 = get_omega(ZR, 2 * params.n, 1729)
    commitment = PolyCommitHybrid(g, h, ZR, multiexp)
    matrices = _sharing_matrices(params.t, params.n)
    curve_params = (ZR, G1, multiexp, dotprod, blsfft)

    instance = DualChainADKG(
        public_keys,
        private_keys[party_id],
        g,
        h,
        g2,
        params.n,
        params.t,
        params.log_q,
        party_id,
        omega2,
        send,
        recv,
        commitment,
        curve_params,
        matrices,
    )
    protocol_task = asyncio.create_task(instance.run_adkg(time.time()))
    started = time.perf_counter()
    raw_output = None
    base_link_view = None
    h_chain = None
    base_link_elapsed = 0.0
    h_all_powers_elapsed = 0.0
    pending = -1
    try:
        raw_output = await asyncio.wait_for(
            instance.output_queue.get(), timeout=timeout_seconds
        )
        await asyncio.wait_for(protocol_task, timeout=timeout_seconds)

        base_link_started = time.perf_counter()
        base_link_view = await asyncio.wait_for(
            run_base_link_party(
                instance=instance,
                raw_output=raw_output,
                params=params,
                g=g,
                h=h,
            ),
            timeout=timeout_seconds,
        )
        base_link_elapsed = time.perf_counter() - base_link_started

        h_started = time.perf_counter()
        h_chain = await asyncio.wait_for(
            run_h_all_powers_party(
                instance=instance,
                raw_output=raw_output,
                t_commits_h=base_link_view.t_commits_h,
                base_h=h,
                params=params,
            ),
            timeout=timeout_seconds,
        )
        h_all_powers_elapsed = time.perf_counter() - h_started

        g2_powers = tuple(instance.gp_task.result())
        party_output = PartyOutput(
            party_id=party_id,
            alpha_share=raw_output[2],
            g_chain=tuple(raw_output[7]),
            h_chain=tuple(h_chain),
            powers_of_two_g1=tuple(
                raw_output[6][index][0] for index in range(params.log_q + 1)
            ),
            t_commits_g=tuple(
                tuple(raw_output[6][index])
                for index in range(params.log_q + 1)
            ),
            powers_of_two_h1=tuple(row[0] for row in base_link_view.t_commits_h),
            t_commits_h=base_link_view.t_commits_h,
            base_link_messages=base_link_view.messages,
            powers_of_two_g2=g2_powers,
            g2=g2,
            alpha_g2=g2_powers[0],
        )
        phase_values = {
            "setup": instance.setup_elapsed_seconds,
            "squaring": instance.squaring_elapsed_seconds,
            "g2": instance.g2_powers_elapsed_seconds,
            "g_all": instance.ap_g_elapsed_seconds,
        }
    finally:
        pending = await _shutdown((instance,), (protocol_task,))

    if raw_output is None or base_link_view is None or h_chain is None:
        raise RuntimeError("the distributed setup party did not produce output")
    return DistributedPartyResult(
        params=params,
        parties=(party_output,),
        g=g,
        h=h,
        g2=g2,
        elapsed_seconds=time.perf_counter() - started,
        setup_elapsed_seconds=phase_values["setup"],
        squaring_elapsed_seconds=phase_values["squaring"],
        g2_powers_elapsed_seconds=phase_values["g2"],
        base_link_elapsed_seconds=base_link_elapsed,
        g_all_powers_elapsed_seconds=phase_values["g_all"],
        h_all_powers_elapsed_seconds=h_all_powers_elapsed,
        pending_protocol_tasks=pending,
    )
