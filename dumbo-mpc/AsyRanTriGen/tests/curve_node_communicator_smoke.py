"""Stage 3-6 integration and sender-identity attack smoke test."""

import asyncio
import pickle
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvloop
import zmq
from zmq.asyncio import Context

from beaver.config import NodeDetails
from beaver.ipc import NodeCommunicator


MESSAGE_TIMEOUT = 2.0
REJECTION_TIMEOUT = 0.75


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


def _auth_config(party_id, keypairs):
    public_keys = [public.decode("ascii") for public, _ in keypairs]
    return {
        "curve_public_key": public_keys[party_id],
        "curve_secret_key": keypairs[party_id][1].decode("ascii"),
        "curve_public_keys": public_keys,
        "curve_zap_domain": "continuum-node-smoke",
        "run_id": "sender-binding-smoke",
    }


def _curve_dealer(context, identity, client_pair, server_public_key, endpoint):
    dealer = context.socket(zmq.DEALER)
    dealer.linger = 0
    dealer.identity = identity
    dealer.curve_publickey = client_pair[0]
    dealer.curve_secretkey = client_pair[1]
    dealer.curve_serverkey = server_public_key
    dealer.connect(endpoint)
    return dealer


async def _expect_no_protocol_message(communicator):
    try:
        await asyncio.wait_for(communicator.recv(), REJECTION_TIMEOUT)
    except asyncio.TimeoutError:
        return
    raise AssertionError("an unauthenticated or spoofed message reached the protocol")


async def run_smoke_test():
    keypairs = [zmq.curve_keypair() for _ in range(3)]
    ports = _reserve_local_ports(3)
    peers = [NodeDetails("127.0.0.1", port) for port in ports]
    endpoint = f"tcp://127.0.0.1:{ports[0]}"
    attacker_context = Context(io_threads=1)

    communicator = NodeCommunicator(
        peers,
        0,
        linger_timeout=0,
        drain_on_exit=False,
        auth_mode="curve",
        auth_config=_auth_config(0, keypairs),
        readiness_barrier=False,
    )

    try:
        async with communicator:
            valid = _curve_dealer(
                attacker_context, b"1", keypairs[1], keypairs[0][0], endpoint
            )
            try:
                message = {"case": "valid", "sender": 1}
                await valid.send(pickle.dumps(message))
                sender, received = await asyncio.wait_for(
                    communicator.recv(), MESSAGE_TIMEOUT
                )
                if sender != 1 or received != message:
                    raise AssertionError(
                        f"authenticated sender mismatch: sender={sender}, msg={received!r}"
                    )
            finally:
                valid.close(linger=0)

            # Party 1 authenticates with its legitimate CURVE key but claims the
            # routing identity of party 2.  The protocol must receive nothing.
            spoofed = _curve_dealer(
                attacker_context, b"2", keypairs[1], keypairs[0][0], endpoint
            )
            try:
                await spoofed.send(pickle.dumps({"case": "identity-spoof"}))
                await _expect_no_protocol_message(communicator)
            finally:
                spoofed.close(linger=0)
            if communicator.identity_spoofing_count < 1:
                raise AssertionError("the identity-spoofing event was not recorded")

            # A cryptographically valid but unregistered client key must be
            # rejected by ZAP before its payload reaches the receive loop.
            unknown_pair = zmq.curve_keypair()
            unknown = _curve_dealer(
                attacker_context, b"1", unknown_pair, keypairs[0][0], endpoint
            )
            try:
                await unknown.send(pickle.dumps({"case": "unknown-client"}))
                await _expect_no_protocol_message(communicator)
            finally:
                unknown.close(linger=0)
            if communicator._curve_credentials.denied_count < 1:
                raise AssertionError("the unknown CURVE key was not rejected by ZAP")
    finally:
        attacker_context.destroy(linger=0)


def main():
    uvloop.run(run_smoke_test())
    print(
        "PASS: authenticated sender mapping, identity-spoof rejection, "
        "unknown-client rejection, and clean shutdown"
    )


if __name__ == "__main__":
    main()
