"""One process in the standalone authenticated committee-election benchmark."""

import asyncio
import base64
import json
import os
import pickle

from beaver.admpc_config import HbmpcConfig
from beaver.ipc import ProcessProgramRunner
from committee_election.model import CandidateRegistry, ElectionContext
from committee_election.network import run_network_election


METRICS_MARKER = "COMMITTEE_ELECTION_METRICS "
FINISHED_MARKER = "COMMITTEE_ELECTION_FINISHED"


async def run():
    extras = HbmpcConfig.extras
    public_key = pickle.loads(base64.b64decode(extras["public_key"]))
    private_key = pickle.loads(base64.b64decode(extras["private_key"]))
    registry = CandidateRegistry.from_dict(extras["election_registry"])
    context = ElectionContext.for_registry(
        run_id=extras["run_id"],
        source_committee_id="P1",
        target_epoch=2,
        registry=registry,
    )
    omit_local_id = os.getenv("COMMITTEE_ELECTION_OMIT_LOCAL_ID")
    omit_share = omit_local_id is not None and int(omit_local_id) == HbmpcConfig.my_id
    timeout = float(os.getenv("COMMITTEE_ELECTION_TIMEOUT_SECONDS", "30"))
    tag = f"committee_election:share:{context.target_epoch}"
    async with ProcessProgramRunner(
        HbmpcConfig.peers,
        HbmpcConfig.N,
        HbmpcConfig.t,
        HbmpcConfig.my_send_id,
        auth_config=extras,
        drain_on_exit=True,
    ) as runner:
        send, recv = runner.get_send_recv(tag)
        bytes_before = runner.node_communicator.bytes_sent
        result = await run_network_election(
            local_id=HbmpcConfig.my_id,
            public_key=public_key,
            private_key=private_key,
            registry=registry,
            context=context,
            participant_global_ids=tuple(range(HbmpcConfig.N)),
            send=send,
            recv=recv,
            omit_share=omit_share,
            timeout=timeout,
        )
        await asyncio.sleep(0.05)
        bytes_sent = runner.node_communicator.bytes_sent - bytes_before
        metrics = result.metrics_dict(
            n=HbmpcConfig.N,
            t=HbmpcConfig.t,
            registry=registry,
            context=context,
            bytes_sent_remote=bytes_sent,
            channel_setup_ms=runner.node_communicator.channel_setup_ms or 0.0,
        )
        metrics["omit_share"] = omit_share
        print(METRICS_MARKER + json.dumps(metrics, sort_keys=True), flush=True)
        print(FINISHED_MARKER, flush=True)


def main():
    HbmpcConfig.load_config()
    asyncio.run(run())


if __name__ == "__main__":
    main()
