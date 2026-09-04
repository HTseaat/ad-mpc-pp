"""Standalone CURVE + ZAP smoke test for the current PyZMQ/uvloop stack.

This intentionally does not use NodeCommunicator.  It isolates the transport
lifecycle before CURVE configuration is integrated with the MPC protocol.
"""

import argparse
import asyncio
import tempfile
from pathlib import Path

import uvloop
import zmq
from zmq import auth
from zmq.asyncio import Context
from zmq.auth.asyncio import AsyncioAuthenticator


ZAP_DOMAIN = "continuum-curve-smoke"
DEFAULT_TIMEOUT = 2.0
REJECTION_TIMEOUT = 0.75


def _configure_server(router, server_public_key, server_secret_key):
    router.curve_publickey = server_public_key
    router.curve_secretkey = server_secret_key
    router.curve_server = True
    router.zap_domain = ZAP_DOMAIN.encode("ascii")


def _configure_client(dealer, client_public_key, client_secret_key, server_key):
    dealer.curve_publickey = client_public_key
    dealer.curve_secretkey = client_secret_key
    dealer.curve_serverkey = server_key


async def _valid_round_trip(
    context,
    server_public_key,
    server_secret_key,
    client_public_key,
    client_secret_key,
    timeout,
):
    router = context.socket(zmq.ROUTER)
    dealer = context.socket(zmq.DEALER)
    router.linger = 0
    dealer.linger = 0

    try:
        _configure_server(router, server_public_key, server_secret_key)
        port = router.bind_to_random_port("tcp://127.0.0.1")

        _configure_client(
            dealer,
            client_public_key,
            client_secret_key,
            server_public_key,
        )
        dealer.connect(f"tcp://127.0.0.1:{port}")

        await dealer.send(b"curve-ping")
        incoming = await asyncio.wait_for(router.recv_multipart(), timeout)
        if incoming[-1] != b"curve-ping":
            raise AssertionError(f"unexpected server payload: {incoming[-1]!r}")

        await router.send_multipart([incoming[0], b"curve-pong"])
        reply = await asyncio.wait_for(dealer.recv(), timeout)
        if reply != b"curve-pong":
            raise AssertionError(f"unexpected client payload: {reply!r}")
    finally:
        dealer.close(linger=0)
        router.close(linger=0)


async def _wrong_server_key_is_rejected(
    context,
    server_public_key,
    server_secret_key,
    client_public_key,
    client_secret_key,
):
    router = context.socket(zmq.ROUTER)
    dealer = context.socket(zmq.DEALER)
    router.linger = 0
    dealer.linger = 0

    try:
        _configure_server(router, server_public_key, server_secret_key)
        port = router.bind_to_random_port("tcp://127.0.0.1")

        wrong_server_public_key, _ = zmq.curve_keypair()
        _configure_client(
            dealer,
            client_public_key,
            client_secret_key,
            wrong_server_public_key,
        )
        dealer.connect(f"tcp://127.0.0.1:{port}")
        await dealer.send(b"must-not-be-delivered")

        try:
            await asyncio.wait_for(router.recv_multipart(), REJECTION_TIMEOUT)
        except asyncio.TimeoutError:
            return
        raise AssertionError("a client using the wrong server key delivered a message")
    finally:
        dealer.close(linger=0)
        router.close(linger=0)


async def run_smoke_test(timeout=DEFAULT_TIMEOUT):
    if not zmq.has("curve"):
        raise RuntimeError("the installed libzmq/PyZMQ build does not support CURVE")

    context = Context(io_threads=1)
    authenticator = AsyncioAuthenticator(context)
    authenticator_started = False

    try:
        with tempfile.TemporaryDirectory(prefix="continuum-curve-smoke-") as temp_dir:
            temp_path = Path(temp_dir)
            server_dir = temp_path / "server"
            allowed_clients_dir = temp_path / "allowed-clients"
            server_dir.mkdir()
            allowed_clients_dir.mkdir()

            server_public_file, server_secret_file = auth.create_certificates(
                server_dir, "server"
            )
            client_public_file, client_secret_file = auth.create_certificates(
                allowed_clients_dir, "client"
            )
            server_public_key, _ = auth.load_certificate(server_public_file)
            _, server_secret_key = auth.load_certificate(server_secret_file)
            client_public_key, _ = auth.load_certificate(client_public_file)
            _, client_secret_key = auth.load_certificate(client_secret_file)

            authenticator.start()
            authenticator_started = True
            authenticator.configure_curve(
                domain=ZAP_DOMAIN,
                location=str(allowed_clients_dir),
            )
            await _valid_round_trip(
                context,
                server_public_key,
                server_secret_key,
                client_public_key,
                client_secret_key,
                timeout,
            )
            await _wrong_server_key_is_rejected(
                context,
                server_public_key,
                server_secret_key,
                client_public_key,
                client_secret_key,
            )
    finally:
        if authenticator_started:
            authenticator.stop()
        context.destroy(linger=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    uvloop.run(run_smoke_test(timeout=args.timeout))
    print("PASS: CURVE+ZAP round trip, wrong-server-key rejection, and clean shutdown")


if __name__ == "__main__":
    main()
