"""Authenticated network transport for one-party-per-host setup runs.

The locked qsdh-py snapshot ships a plain ZeroMQ transport whose DEALER
identity is unauthenticated.  This module keeps the upstream protocol API
(``send(destination, message)`` / ``await recv()``) while authenticating every
peer with a run-scoped CURVE key registry.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pickle
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

import zmq
from zmq.asyncio import Context
from zmq.auth.asyncio import AsyncioAuthenticator
from zmq.utils import z85


AUTH_MODE = "curve"
CHANNEL_CONTROL_MARKER = "trusted-setup-curve-channel-control-v1"
CHANNEL_CONTROL_PING = "ping"
CHANNEL_CONTROL_ACK = "ack"
TRANSPORT_SCHEMA = 1


def _validated_z85_key(name: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a 40-character Z85 string")
    try:
        encoded = value.encode("ascii")
        decoded = z85.decode(encoded)
    except (UnicodeEncodeError, KeyError, ValueError) as exc:
        raise ValueError(f"{name} is not valid Z85") from exc
    if len(encoded) != 40 or len(decoded) != 32:
        raise ValueError(f"{name} must encode one 32-byte CURVE key")
    return encoded


def _transport_public_payload(
    *, run_id: str, zap_domain: str, public_keys: Sequence[str]
) -> dict[str, Any]:
    return {
        "auth_mode": AUTH_MODE,
        "curve_public_keys": list(public_keys),
        "curve_zap_domain": zap_domain,
        "run_id": run_id,
        "schema": TRANSPORT_SCHEMA,
    }


def transport_digest(
    *, run_id: str, zap_domain: str, public_keys: Sequence[str]
) -> str:
    payload = json.dumps(
        _transport_public_payload(
            run_id=run_id,
            zap_domain=zap_domain,
            public_keys=public_keys,
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def build_curve_transport_configs(run_id: str, n: int) -> tuple[dict[str, Any], ...]:
    """Generate one private transport record per party.

    Callers must deliver only record ``i`` to party ``i``.  The common digest
    covers the public registry and run domain; it deliberately excludes every
    party's secret key.
    """

    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id must be a non-empty string")
    if type(n) is not int or n < 1:
        raise ValueError("n must be a positive integer")
    if not zmq.has("curve"):
        raise RuntimeError("the installed libzmq/PyZMQ build lacks CURVE support")
    keypairs = [zmq.curve_keypair() for _ in range(n)]
    public_keys = [public.decode("ascii") for public, _ in keypairs]
    zap_domain = f"continuum-trusted-setup-{run_id}"
    digest = transport_digest(
        run_id=run_id,
        zap_domain=zap_domain,
        public_keys=public_keys,
    )
    return tuple(
        {
            **_transport_public_payload(
                run_id=run_id,
                zap_domain=zap_domain,
                public_keys=public_keys,
            ),
            "curve_public_key": public_keys[party_id],
            "curve_secret_key": keypairs[party_id][1].decode("ascii"),
            "transport_digest": digest,
        }
        for party_id in range(n)
    )


def validate_curve_transport_config(
    config: Mapping[str, Any], *, party_id: int, n: int, run_id: str
) -> dict[str, Any]:
    if not zmq.has("curve"):
        raise RuntimeError("the installed libzmq/PyZMQ build lacks CURVE support")
    if not isinstance(config, Mapping):
        raise ValueError("transport configuration must be an object")
    if type(party_id) is not int or not 0 <= party_id < n:
        raise ValueError("party_id must index the committee")
    if config.get("schema") != TRANSPORT_SCHEMA:
        raise ValueError("unsupported transport schema")
    if config.get("auth_mode") != AUTH_MODE:
        raise ValueError("trusted setup distributed runs require CURVE")
    if config.get("run_id") != run_id:
        raise ValueError("transport run_id does not match setup run_id")

    registry_values = config.get("curve_public_keys")
    if not isinstance(registry_values, list) or len(registry_values) != n:
        raise ValueError("curve_public_keys must contain one key per party")
    registry = tuple(
        _validated_z85_key(f"curve_public_keys[{index}]", value)
        for index, value in enumerate(registry_values)
    )
    if len(set(registry)) != n:
        raise ValueError("curve_public_keys contains duplicate keys")
    public_key = _validated_z85_key(
        "curve_public_key", config.get("curve_public_key")
    )
    secret_key = _validated_z85_key(
        "curve_secret_key", config.get("curve_secret_key")
    )
    if public_key != registry[party_id]:
        raise ValueError("curve_public_key does not match this party")
    if zmq.curve_public(secret_key) != public_key:
        raise ValueError("curve_secret_key does not match curve_public_key")
    zap_domain = config.get("curve_zap_domain")
    if not isinstance(zap_domain, str) or not zap_domain:
        raise ValueError("curve_zap_domain must be a non-empty string")
    expected_digest = transport_digest(
        run_id=run_id,
        zap_domain=zap_domain,
        public_keys=registry_values,
    )
    if config.get("transport_digest") != expected_digest:
        raise ValueError("transport public-registry digest mismatch")
    return {
        "public_key": public_key,
        "secret_key": secret_key,
        "public_keys": registry,
        "party_by_user_id": {key: index for index, key in enumerate(registry)},
        "zap_domain": zap_domain,
        "zap_domain_bytes": zap_domain.encode("utf-8"),
        "run_id": run_id,
        "transport_digest": expected_digest,
    }


def load_node_transport(path: Path | str, *, party_id: int, n: int, run_id: str):
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load node configuration {source}: {exc}") from exc
    return validate_curve_transport_config(
        value.get("transport"), party_id=party_id, n=n, run_id=run_id
    )


class CurveCredentialsProvider:
    def __init__(self, domain: str, allowed_keys: Sequence[bytes]):
        self.domain = domain
        self.allowed_keys = frozenset(allowed_keys)
        self.denied_count = 0

    def callback(self, domain: str, client_key: bytes) -> bool:
        allowed = domain == self.domain and client_key in self.allowed_keys
        if not allowed:
            self.denied_count += 1
        return allowed


class CurveNodeCommunicator:
    """CURVE-authenticated all-to-all transport with exact payload counters."""

    _STOP = object()

    def __init__(
        self,
        peers: Sequence[str],
        party_id: int,
        transport_config: Mapping[str, Any],
        *,
        readiness_timeout: float = 60.0,
        linger_seconds: float = 2.0,
    ):
        if type(party_id) is not int or not 0 <= party_id < len(peers):
            raise ValueError("party_id must index peers")
        if readiness_timeout <= 0 or linger_seconds < 0:
            raise ValueError("invalid transport timeout")
        self.peers = tuple(self._parse_peer(peer) for peer in peers)
        self.party_id = party_id
        self.config = dict(transport_config)
        self.readiness_timeout = float(readiness_timeout)
        self.linger_milliseconds = int(linger_seconds * 1000)
        self.context = Context(io_threads=1)

        self._receiver_queue: asyncio.Queue = asyncio.Queue()
        self._sender_queues = [
            self._receiver_queue if index == party_id else asyncio.Queue()
            for index in range(len(peers))
        ]
        self._dealer_tasks: list[asyncio.Task] = []
        self._router_task: asyncio.Task | None = None
        self._sockets: list[Any] = []
        self._authenticator: AsyncioAuthenticator | None = None
        self._credentials: CurveCredentialsProvider | None = None
        self._expected = set(range(len(peers))) - {party_id}
        self._pings: set[int] = set()
        self._acks: set[int] = set()
        self._ready = asyncio.Event()

        self.sent_bytes = 0
        self.sent_messages = 0
        self.sent_bytes_by_tag: defaultdict[str, int] = defaultdict(int)
        self.sent_messages_by_tag: defaultdict[str, int] = defaultdict(int)
        self.invalid_auth_metadata_count = 0
        self.identity_spoofing_count = 0
        self.channel_setup_seconds = 0.0

    @staticmethod
    def _parse_peer(peer: str) -> tuple[str, int]:
        if not isinstance(peer, str) or peer.count(":") != 1:
            raise ValueError(f"invalid peer endpoint: {peer!r}")
        host, port_text = peer.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"invalid peer port: {peer!r}") from exc
        if not host or not 1 <= port <= 65535:
            raise ValueError(f"invalid peer endpoint: {peer!r}")
        return host, port

    @staticmethod
    def _control_message(run_id: str, kind: str) -> tuple[str, str, str]:
        return CHANNEL_CONTROL_MARKER, run_id, kind

    @staticmethod
    def _is_control(message: Any) -> bool:
        return (
            isinstance(message, tuple)
            and len(message) == 3
            and message[0] == CHANNEL_CONTROL_MARKER
            and message[2] in (CHANNEL_CONTROL_PING, CHANNEL_CONTROL_ACK)
        )

    @staticmethod
    def _outer_tag(message: Any) -> str:
        current = message
        for _ in range(8):
            if not isinstance(current, (tuple, list)) or not current:
                break
            tag = current[0]
            if isinstance(tag, str) and tag:
                return tag
            if tag == "" and len(current) > 1:
                current = current[1]
                continue
            break
        return "APP"

    def send(self, destination: int, message: Any) -> None:
        if type(destination) is not int or not 0 <= destination < len(self.peers):
            raise ValueError("destination must index peers")
        if destination == self.party_id:
            self._receiver_queue.put_nowait((self.party_id, message))
            return
        raw = pickle.dumps(message)
        if not self._is_control(message):
            tag = self._outer_tag(message)
            self.sent_bytes += len(raw)
            self.sent_messages += 1
            self.sent_bytes_by_tag[tag] += len(raw)
            self.sent_messages_by_tag[tag] += 1
        self._sender_queues[destination].put_nowait(raw)

    async def recv(self):
        return await self._receiver_queue.get()

    async def __aenter__(self):
        started = time.perf_counter()
        try:
            await self._setup()
            await self._wait_for_readiness()
        except BaseException:
            await self._abort()
            raise
        self.channel_setup_seconds = time.perf_counter() - started
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        for index, queue in enumerate(self._sender_queues):
            if index != self.party_id:
                queue.put_nowait(self._STOP)
        errors = await asyncio.gather(*self._dealer_tasks, return_exceptions=True)
        if self._router_task is not None:
            self._router_task.cancel()
            await asyncio.gather(self._router_task, return_exceptions=True)
        self._stop_authenticator()
        self._close_sockets()
        self.context.destroy(linger=self.linger_milliseconds)
        if exc_type is None:
            for error in errors:
                if isinstance(error, BaseException):
                    raise error

    async def _abort(self):
        for task in self._dealer_tasks:
            task.cancel()
        if self._router_task is not None:
            self._router_task.cancel()
        tasks = list(self._dealer_tasks)
        if self._router_task is not None:
            tasks.append(self._router_task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._stop_authenticator()
        self._close_sockets()
        self.context.destroy(linger=0)

    def _stop_authenticator(self):
        if self._authenticator is not None:
            self._authenticator.stop()
            self._authenticator = None

    def _close_sockets(self):
        for socket in self._sockets:
            socket.close(linger=0)
        self._sockets.clear()

    async def _setup(self):
        self._credentials = CurveCredentialsProvider(
            self.config["zap_domain"], self.config["public_keys"]
        )
        self._authenticator = AsyncioAuthenticator(self.context)
        self._authenticator.start()
        self._authenticator.configure_curve_callback(
            domain=self.config["zap_domain"],
            credentials_provider=self._credentials,
        )

        router = self.context.socket(zmq.ROUTER)
        router.curve_publickey = self.config["public_key"]
        router.curve_secretkey = self.config["secret_key"]
        router.curve_server = True
        router.zap_domain = self.config["zap_domain_bytes"]
        router.linger = self.linger_milliseconds
        router.bind(f"tcp://*:{self.peers[self.party_id][1]}")
        self._sockets.append(router)
        self._router_task = asyncio.create_task(self._recv_loop(router))

        for peer_id, (host, port) in enumerate(self.peers):
            if peer_id == self.party_id:
                continue
            dealer = self.context.socket(zmq.DEALER)
            dealer.curve_publickey = self.config["public_key"]
            dealer.curve_secretkey = self.config["secret_key"]
            dealer.curve_serverkey = self.config["public_keys"][peer_id]
            dealer.identity = str(self.party_id).encode("ascii")
            dealer.linger = self.linger_milliseconds
            dealer.connect(f"tcp://{host}:{port}")
            self._sockets.append(dealer)
            self._dealer_tasks.append(
                asyncio.create_task(
                    self._send_loop(self._sender_queues[peer_id], dealer)
                )
            )

    async def _wait_for_readiness(self):
        if not self._expected:
            return
        ping = self._control_message(self.config["run_id"], CHANNEL_CONTROL_PING)
        for peer_id in sorted(self._expected):
            self.send(peer_id, ping)
        try:
            await asyncio.wait_for(self._ready.wait(), self.readiness_timeout)
        except asyncio.TimeoutError as exc:
            missing_pings = sorted(self._expected - self._pings)
            missing_acks = sorted(self._expected - self._acks)
            raise RuntimeError(
                "CURVE readiness timed out; "
                f"missing_pings={missing_pings}, missing_acks={missing_acks}"
            ) from exc

    def _handle_control(self, sender: int, message: Any) -> bool:
        if not self._is_control(message):
            return False
        if message[1] != self.config["run_id"]:
            return True
        if message[2] == CHANNEL_CONTROL_PING:
            self._pings.add(sender)
            self.send(
                sender,
                self._control_message(self.config["run_id"], CHANNEL_CONTROL_ACK),
            )
        else:
            self._acks.add(sender)
        if self._expected <= self._pings and self._expected <= self._acks:
            self._ready.set()
        return True

    async def _recv_loop(self, router):
        while True:
            frames = await router.recv_multipart(copy=False)
            if len(frames) != 2:
                self.invalid_auth_metadata_count += 1
                continue
            routing_frame, payload_frame = frames
            try:
                user_id = routing_frame["User-Id"]
            except (KeyError, zmq.ZMQError):
                self.invalid_auth_metadata_count += 1
                continue
            if isinstance(user_id, str):
                user_id = user_id.encode("ascii")
            sender = self.config["party_by_user_id"].get(user_id)
            if sender is None:
                self.invalid_auth_metadata_count += 1
                continue
            if bytes(routing_frame) != str(sender).encode("ascii"):
                self.identity_spoofing_count += 1
                continue
            message = pickle.loads(bytes(payload_frame))
            if self._handle_control(sender, message):
                continue
            self._receiver_queue.put_nowait((sender, message))

    async def _send_loop(self, queue: asyncio.Queue, dealer):
        while True:
            raw = await queue.get()
            if raw is self._STOP:
                return
            await dealer.send_multipart([raw])

    def snapshot(self) -> dict[str, Any]:
        return {
            "auth_mode": AUTH_MODE,
            "channel_setup_seconds": self.channel_setup_seconds,
            "curve_denied_count": (
                0 if self._credentials is None else self._credentials.denied_count
            ),
            "identity_spoofing_count": self.identity_spoofing_count,
            "invalid_auth_metadata_count": self.invalid_auth_metadata_count,
            "sent_bytes_by_outer_tag": dict(sorted(self.sent_bytes_by_tag.items())),
            "sent_messages_by_outer_tag": dict(
                sorted(self.sent_messages_by_tag.items())
            ),
            "total_remote_payload_bytes": self.sent_bytes,
            "total_remote_messages": self.sent_messages,
            "transport_digest": self.config["transport_digest"],
        }
