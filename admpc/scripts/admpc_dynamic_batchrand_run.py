"""Run only the paper-required dynamic BatchRand handoff.

The active Figure 8 AD-MPC driver uses BatchBundle in its ``GR`` phase.  The
paper requires an independent BatchRand as well.  This entry point executes
that omitted phase between exactly two adjacent committees so communication
can be measured without running a full circuit.
"""

import asyncio
import os
from types import SimpleNamespace

from pypairing import G1, ZR, blsmultiexp as multiexp, dotprod

from adkg.admpc_dynamic import ADMPC_Multi_Layer_Control
from adkg.ipc import ProcessProgramRunner
from adkg.poly_commit_hybrid import PolyCommitHybrid
from adkg.rand import (
    Rand_Foll,
    Rand_Pre,
    batchrand_batch_count,
    batchrand_extraction_matrix,
)


WIDTH = 100
PROTOCOL_TAG = "GR1"
CONTROL_TAG = "BATCHRAND_CONTROL"


def _keys(count):
    g, h = G1.rand(b"g"), G1.rand(b"h")
    private_keys = [ZR.hash(str(index).encode()) for index in range(count)]
    public_keys = [g ** private_key for private_key in private_keys]
    return g, h, public_keys, private_keys


def _matrix(t, n):
    if n != 3 * t + 1:
        raise ValueError("BatchRand requires n=3*t+1")
    return batchrand_extraction_matrix(ZR, t)


def _test_omitted_dealers(n):
    """Parse the opt-in omission hook used by BatchRand liveness tests."""
    raw = os.environ.get("BATCHRAND_TEST_OMIT_DEALERS", "").strip()
    if not raw:
        return set()
    try:
        dealers = {int(value.strip()) for value in raw.split(",")}
    except ValueError as exc:
        raise ValueError(
            "BATCHRAND_TEST_OMIT_DEALERS must be comma-separated integers"
        ) from exc
    if any(dealer < 0 or dealer >= n for dealer in dealers):
        raise ValueError("BatchRand omitted dealer ID is out of range")
    return dealers


def _metrics_context(n, t, my_id, my_send_id):
    return {
        "implementation": "admpc",
        "experiment": "figure8",
        "protocol_variant": "admpc-batchrand",
        "run_id": os.environ.get("PROTOCOL_OVERHEAD_RUN_ID", "local"),
        "parameters": {
            "committee_size": int(n),
            "threshold": int(t),
            "total_layers": 2,
            "circuit_depth": 1,
            "total_cm": 0,
            "configured_width": WIDTH,
            "expected_batch_size": WIDTH,
            "expected_operations": 1,
            "expected_processes": int(2 * n),
            "proof_metrics_expected": True,
            "evaluation_verifier_mode": "legacy-inner-proof-only",
        },
        "process": {
            "global_process_id": int(my_send_id),
            "local_party_id": int(my_id),
            "physical_layer": int(my_send_id // n),
        },
        "selection": {
            "included_tags": [PROTOCOL_TAG],
            "excluded_tag_prefixes": [CONTROL_TAG],
            "normalization_unit": "sharing",
        },
    }


async def _run(peers, n, t, k, my_id, start_time, layers, my_send_id, total_cm):
    if layers != 2:
        raise ValueError("admpc-batchrand requires exactly two committees (layers=2)")
    if n != 3 * t + 1:
        raise ValueError("BatchRand requires n=3*t+1")

    g, h, public_keys, private_keys = _keys(2 * n)
    control = ADMPC_Multi_Layer_Control(
        n=n, t=t, deg=k, layer_num=2, total_cm=0, pks=public_keys
    )
    pc = PolyCommitHybrid(g, h, ZR, multiexp)
    curve_params = (ZR, G1, multiexp, dotprod)
    matrix = _matrix(t, n)
    physical_layer = my_send_id // n
    rounds = batchrand_batch_count(WIDTH, t)
    omitted_dealers = _test_omitted_dealers(n)
    if len(omitted_dealers) > t:
        raise ValueError("BatchRand test hook may omit at most t dealers")
    common_subset = None

    async with ProcessProgramRunner(
        peers,
        2 * n,
        t,
        my_send_id,
        metrics_context=_metrics_context(n, t, my_id, my_send_id),
    ) as runner:
        runner.node_communicator.register_protocol_batch(
            protocol="batch_rand",
            tag=PROTOCOL_TAG,
            source_layer=0,
            target_layer=1,
            batch_size=WIDTH,
            role="source" if physical_layer == 0 else "destination",
            operation_id="batchrand:1",
            unit="sharing",
        )
        send, recv = runner.get_send_recv(PROTOCOL_TAG)
        control_send, control_recv = runner.get_send_recv(CONTROL_TAG)
        mpc_instance = SimpleNamespace(
            layer_ID=physical_layer,
            admpc_control_instance=control,
            metrics_recorder=runner.node_communicator,
            metrics_normalization_count=WIDTH,
        )
        committee_keys = public_keys[
            physical_layer * n : (physical_layer + 1) * n
        ]
        private_key = private_keys[my_send_id]

        if physical_layer == 0:
            if my_id in omitted_dealers:
                print(f"BatchRand test omission: source dealer {my_id}")
            else:
                batch_rand = Rand_Pre(
                    committee_keys, private_key, g, h, n, t, k, my_id,
                    send, recv, pc, curve_params, matrix, mpc_instance,
                )
                batch_rand.metrics_protocol = "batchrand"
                await batch_rand.run_rand(WIDTH, rounds)
                # The pre API schedules its dealer task and returns immediately.
                await batch_rand.acss_task
            completed_destinations = set()
            while len(completed_destinations) < n:
                sender, message = await control_recv()
                if message == "done" and n <= sender < 2 * n:
                    completed_destinations.add(sender)
        else:
            batch_rand = Rand_Foll(
                committee_keys, private_key, g, h, n, t, k, my_id,
                send, recv, pc, curve_params, matrix, mpc_instance,
            )
            batch_rand.metrics_protocol = "batchrand"
            shares = await batch_rand.run_rand(WIDTH, rounds)
            common_subset = batch_rand.common_subset
            if len(shares) != WIDTH:
                raise RuntimeError(
                    f"BatchRand returned {len(shares)} shares; expected {WIDTH}"
                )
            for source_id in range(n):
                control_send(source_id, "done")

        # Let protocol-owned background tasks consume their final local messages;
        # the transport context then performs the authoritative queue drain.
        await asyncio.sleep(0.25)
        if os.environ.get("PROTOCOL_OVERHEAD_METRICS", "0").lower() in {
            "1", "true", "yes", "on"
        }:
            runner.node_communicator.write_metrics_checkpoint()
        print(
            f"BatchRand Finished: global_id={my_send_id}, "
            f"layer={physical_layer}, rounds={rounds}, width={WIDTH}, "
            f"common_subset={common_subset}"
        )
