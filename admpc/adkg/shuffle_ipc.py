"""Adjacent-only ZeroMQ transport used by the AD-MPC shuffle path."""

import asyncio
import logging
import time
from pickle import loads

import zmq
from zmq import DEALER, IDENTITY, ROUTER
from zmq.auth.asyncio import AsyncioAuthenticator

from adkg.ipc import (
    AUTH_MODE_CURVE,
    CurveCredentialsProvider,
    NodeCommunicator,
)
from adkg.utils.misc import print_exception_callback, subscribe_recv, wrap_send


def adjacent_peer_ids(global_id, n, physical_layers):
    """Return same-committee and adjacent-committee peers, excluding self."""
    if not isinstance(n, int) or n <= 0:
        raise ValueError("n must be a positive integer")
    if not isinstance(physical_layers, int) or physical_layers <= 0:
        raise ValueError("physical_layers must be a positive integer")
    total = n * physical_layers
    if not isinstance(global_id, int) or global_id < 0 or global_id >= total:
        raise ValueError("global_id is outside the configured topology")
    layer = global_id // n
    layers = {layer}
    if layer > 0:
        layers.add(layer - 1)
    if layer + 1 < physical_layers:
        layers.add(layer + 1)
    peers = {
        candidate
        for peer_layer in layers
        for candidate in range(peer_layer * n, (peer_layer + 1) * n)
    }
    peers.discard(global_id)
    return frozenset(peers)


class AdjacentNodeCommunicator(NodeCommunicator):
    def __init__(self, peers_config, my_id, allowed_peer_ids, *args, **kwargs):
        super().__init__(peers_config, my_id, *args, **kwargs)
        allowed = frozenset(allowed_peer_ids)
        invalid = sorted(
            peer for peer in allowed if not isinstance(peer, int) or not 0 <= peer < len(peers_config)
        )
        if invalid or my_id in allowed:
            raise ValueError(
                f"invalid adjacent peer allowlist: invalid={invalid}, self={my_id in allowed}"
            )
        self.allowed_peer_ids = allowed
        self._readiness_expected = set(allowed)
        self.forbidden_peer_message_count = 0

    def send(self, node_id, msg):
        if node_id != self.my_id and node_id not in self.allowed_peer_ids:
            raise ValueError(
                f"forbidden non-adjacent send: source={self.my_id}, destination={node_id}"
            )
        super().send(node_id, msg)

    def _start_curve_authenticator(self):
        allowed_keys = [
            self.curve_config["public_keys"][peer]
            for peer in sorted(self.allowed_peer_ids)
        ]
        self._curve_credentials = CurveCredentialsProvider(
            self.curve_config["zap_domain"], allowed_keys
        )
        self._authenticator = AsyncioAuthenticator(self.zmq_context)
        self._authenticator.start()
        self._authenticator.configure_curve_callback(
            domain=self.curve_config["zap_domain"],
            credentials_provider=self._curve_credentials,
        )

    def snapshot_communication_metrics(self):
        snapshot = super().snapshot_communication_metrics()
        snapshot.update(
            {
                "transport_topology": "adjacent",
                "allowed_remote_peer_count": len(self.allowed_peer_ids),
                "forbidden_peer_message_count": self.forbidden_peer_message_count,
            }
        )
        return snapshot

    async def _setup(self):
        setup_started = time.perf_counter()
        if self.auth_mode == AUTH_MODE_CURVE:
            self._start_curve_authenticator()
        router = self.zmq_context.socket(ROUTER)
        if self.auth_mode == AUTH_MODE_CURVE:
            self._configure_curve_server(router)
        router.bind(f"tcp://*:{self.peers_config[self.my_id].port}")
        self._router_task = asyncio.create_task(self._recv_loop(router))
        self._router_task.add_done_callback(print_exception_callback)

        for peer_id in sorted(self.allowed_peer_ids):
            dealer = self.zmq_context.socket(DEALER)
            if self.auth_mode == AUTH_MODE_CURVE:
                self._configure_curve_client(dealer, peer_id)
            dealer.setsockopt(IDENTITY, str(self.my_id).encode())
            dealer.connect(
                f"tcp://{self.peers_config[peer_id].ip}:"
                f"{self.peers_config[peer_id].port}"
            )
            task = asyncio.create_task(
                self._process_node_messages(
                    peer_id, self._sender_queues[peer_id], dealer.send_multipart
                )
            )
            self._dealer_tasks.append(task)

        if self.auth_mode == AUTH_MODE_CURVE and self.readiness_barrier:
            await self._wait_for_curve_readiness()
            self.channel_setup_ms = (time.perf_counter() - setup_started) * 1000
            print(
                f"my_send_id: {self.my_id} CURVE channel_setup_ms: "
                f"{self.channel_setup_ms:.3f} topology=adjacent "
                f"peers={len(self.allowed_peer_ids)}"
            )

    async def _recv_loop(self, router):
        while True:
            if self.auth_mode != AUTH_MODE_CURVE:
                sender_id, raw_msg = await router.recv_multipart()
                sender_id = int(sender_id)
            else:
                frames = await router.recv_multipart(copy=False)
                if len(frames) != 2:
                    self.invalid_auth_metadata_count += 1
                    continue
                routing_frame, payload_frame = frames
                try:
                    user_id = routing_frame["User-Id"]
                except (KeyError, zmq.ZMQError):
                    user_id = None
                if isinstance(user_id, str):
                    user_id = user_id.encode("ascii", "strict")
                sender_id = self.curve_config["party_by_user_id"].get(user_id)
                if sender_id is None:
                    self.invalid_auth_metadata_count += 1
                    continue
                if bytes(routing_frame) != str(sender_id).encode("ascii"):
                    self.identity_spoofing_count += 1
                    continue
                raw_msg = bytes(payload_frame)

            if sender_id != self.my_id and sender_id not in self.allowed_peer_ids:
                self.forbidden_peer_message_count += 1
                logging.error(
                    "Dropping forbidden non-adjacent message: source=%d destination=%d",
                    sender_id,
                    self.my_id,
                )
                continue
            msg = loads(raw_msg)
            if (
                self.auth_mode == AUTH_MODE_CURVE
                and self._handle_channel_control(sender_id, msg)
            ):
                continue
            self._receiver_queue.put_nowait((sender_id, msg))


class ShuffleProcessProgramRunner:
    """Small runner wrapper that leaves the generic baseline runner untouched."""

    def __init__(
        self,
        peers_config,
        n,
        t,
        my_id,
        allowed_peer_ids,
        **communicator_kwargs,
    ):
        self.n = n
        self.t = t
        self.my_id = my_id
        self.node_communicator = AdjacentNodeCommunicator(
            peers_config,
            my_id,
            allowed_peer_ids,
            **communicator_kwargs,
        )

    def get_send_recv(self, tag):
        return wrap_send(tag, self.send), self.subscribe(tag)

    async def __aenter__(self):
        await self.node_communicator.__aenter__()
        self.subscribe_task, self.subscribe = subscribe_recv(
            self.node_communicator.recv
        )
        self.send = self.node_communicator.send
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.node_communicator.__aexit__(exc_type, exc, tb)
        self.subscribe_task.cancel()
        await asyncio.gather(self.subscribe_task, return_exceptions=True)
