"""Authenticated full-mesh readiness barrier smoke tests."""

import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvloop
import zmq

import beaver.ipc as ipc
from beaver.config import NodeDetails
from beaver.ipc import NodeCommunicator


def _reserve_local_ports(count):
    reservations = []
    try:
        for _ in range(count):
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservation.bind(("127.0.0.1", 0))
            reservations.append(reservation)
        return [reservation.getsockname()[1] for reservation in reservations]
    finally:
        for reservation in reservations:
            reservation.close()


def _auth_config(party_id, own_keypair, registry, run_id):
    return {
        "curve_public_key": own_keypair[0].decode("ascii"),
        "curve_secret_key": own_keypair[1].decode("ascii"),
        "curve_public_keys": [key.decode("ascii") for key in registry],
        "curve_zap_domain": "continuum-readiness-smoke",
        "run_id": run_id,
    }


async def _enter_and_close(communicator):
    async with communicator:
        if communicator.channel_setup_ms is None:
            raise AssertionError("readiness completed without channel_setup_ms")
        return communicator.channel_setup_ms


def _communicator(peers, party_id, auth_config, timeout):
    return NodeCommunicator(
        peers,
        party_id,
        linger_timeout=0,
        auth_mode="curve",
        auth_config=auth_config,
        readiness_timeout=timeout,
    )


async def _valid_full_mesh_case():
    keypairs = [zmq.curve_keypair() for _ in range(2)]
    registry = [pair[0] for pair in keypairs]
    peers = [
        NodeDetails("127.0.0.1", port) for port in _reserve_local_ports(2)
    ]
    communicators = [
        _communicator(
            peers,
            party_id,
            _auth_config(
                party_id, keypairs[party_id], registry, "readiness-valid-run"
            ),
            2.0,
        )
        for party_id in range(2)
    ]
    setup_times = await asyncio.gather(
        *(_enter_and_close(communicator) for communicator in communicators)
    )
    if not all(setup_time > 0 for setup_time in setup_times):
        raise AssertionError(f"invalid channel setup measurements: {setup_times!r}")


async def _wrong_key_times_out_case():
    keypairs = [zmq.curve_keypair() for _ in range(2)]
    wrong_party_one_public, _ = zmq.curve_keypair()
    peers = [
        NodeDetails("127.0.0.1", port) for port in _reserve_local_ports(2)
    ]
    configs = [
        _auth_config(
            0,
            keypairs[0],
            [keypairs[0][0], wrong_party_one_public],
            "readiness-wrong-key-run",
        ),
        _auth_config(
            1,
            keypairs[1],
            [keypairs[0][0], keypairs[1][0]],
            "readiness-wrong-key-run",
        ),
    ]
    results = await asyncio.gather(
        *(
            _enter_and_close(_communicator(peers, party_id, configs[party_id], 0.5))
            for party_id in range(2)
        ),
        return_exceptions=True,
    )
    if not all(
        isinstance(result, RuntimeError) and "CURVE readiness timed out" in str(result)
        for result in results
    ):
        raise AssertionError(f"wrong-key readiness results were not explicit: {results!r}")


async def run_smoke_test():
    # Avoid creating cpu_count() I/O threads per in-process test communicator.
    ipc.cpu_count = lambda: 1
    await _valid_full_mesh_case()
    await _wrong_key_times_out_case()


def main():
    uvloop.run(run_smoke_test())
    print("PASS: full-mesh readiness and bounded wrong-key failure")


if __name__ == "__main__":
    main()
