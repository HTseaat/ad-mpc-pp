import logging
import asyncio
import hashlib
import json
import os
import time

import zmq
from zmq import ROUTER, DEALER, IDENTITY
from zmq.asyncio import Context
from zmq.auth.asyncio import AsyncioAuthenticator
from zmq.utils import z85
from pickle import dumps, loads
from psutil import cpu_count

from adkg.mpc import Mpc
from adkg.config import HbmpcConfig, ConfigVars
from adkg.utils.misc import wrap_send, subscribe_recv
from adkg.utils.misc import print_exception_callback
from adkg.communication_metrics import CommunicationMetricsArtifact
from collections import defaultdict


AUTH_MODE_ENV = "ZMQ_AUTH_MODE"
AUTH_MODE_NULL = "null"
AUTH_MODE_CURVE = "curve"
VALID_AUTH_MODES = frozenset((AUTH_MODE_NULL, AUTH_MODE_CURVE))
CURVE_CONFIG_DIR_ENV = "ZMQ_CURVE_CONFIG_DIR"
CURVE_PUBLIC_KEY = "curve_public_key"
CURVE_SECRET_KEY = "curve_secret_key"
CURVE_PUBLIC_KEYS = "curve_public_keys"
CURVE_ZAP_DOMAIN = "curve_zap_domain"
CURVE_RUN_ID = "run_id"
CURVE_READY_TIMEOUT_ENV = "ZMQ_CURVE_READY_TIMEOUT"
CURVE_READY_TIMEOUT_DEFAULT = 10.0
MAX_SOCKETS_ENV = "ZMQ_MAX_SOCKETS"
MAX_SOCKETS_DEFAULT = 4096
MAX_SOCKETS_HEADROOM = 64
IO_THREADS_ENV = "ZMQ_IO_THREADS"
CHANNEL_CONTROL_MARKER = "admpc-curve-channel-control-v1"
CHANNEL_CONTROL_PING = "ping"
CHANNEL_CONTROL_ACK = "ack"


def resolve_auth_mode(auth_mode=None):
    value = os.environ.get(AUTH_MODE_ENV, AUTH_MODE_NULL) if auth_mode is None else auth_mode
    if not isinstance(value, str):
        raise ValueError("auth_mode must be a string")
    value = value.strip().lower()
    if value not in VALID_AUTH_MODES:
        valid_modes = ", ".join(sorted(VALID_AUTH_MODES))
        raise ValueError(
            f"unsupported ZeroMQ auth mode {value!r}; expected one of: {valid_modes}"
        )
    return value


def resolve_readiness_timeout(readiness_timeout=None):
    value = (
        os.environ.get(CURVE_READY_TIMEOUT_ENV, CURVE_READY_TIMEOUT_DEFAULT)
        if readiness_timeout is None
        else readiness_timeout
    )
    try:
        value = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{CURVE_READY_TIMEOUT_ENV} must be a positive number of seconds"
        ) from exc
    if value <= 0:
        raise ValueError(
            f"{CURVE_READY_TIMEOUT_ENV} must be a positive number of seconds"
        )
    return value


def resolve_max_sockets(peer_count, max_sockets=None):
    """Return a context socket limit large enough for one socket per peer."""
    if not isinstance(peer_count, int) or peer_count <= 0:
        raise ValueError("peer_count must be a positive integer")
    value = (
        os.environ.get(
            MAX_SOCKETS_ENV,
            max(MAX_SOCKETS_DEFAULT, peer_count + MAX_SOCKETS_HEADROOM),
        )
        if max_sockets is None
        else max_sockets
    )
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{MAX_SOCKETS_ENV} must be a positive integer") from exc
    if value < peer_count:
        raise ValueError(
            f"{MAX_SOCKETS_ENV}={value} is too small for {peer_count} peer sockets"
        )
    return value


def resolve_io_threads(io_threads=None):
    """Return the libzmq I/O thread count for this process.

    Keep the distributed-run default unchanged while allowing a large
    single-host campaign to cap every process with ``ZMQ_IO_THREADS=1``.
    """
    value = (
        os.environ.get(IO_THREADS_ENV, cpu_count() or 1)
        if io_threads is None
        else io_threads
    )
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{IO_THREADS_ENV} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{IO_THREADS_ENV} must be a positive integer")
    return value


def _validated_z85_key(name, value):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a 40-character Z85 string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must contain only ASCII Z85 characters") from exc
    if len(encoded) != 40:
        raise ValueError(f"{name} must be exactly 40 Z85 bytes")
    try:
        decoded = z85.decode(encoded)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{name} is not valid Z85") from exc
    if len(decoded) != 32:
        raise ValueError(f"{name} must decode to a 32-byte CURVE key")
    return encoded


def _load_curve_config_from_env(my_id):
    config_dir = os.environ.get(CURVE_CONFIG_DIR_ENV)
    if not config_dir:
        return None
    config_path = os.path.join(config_dir, f"local.{my_id}.json")
    try:
        with open(config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot load CURVE config {config_path}: {exc}") from exc
    return config.get("extra", config)


def validate_curve_config(peers_config, my_id, auth_config):
    if not zmq.has("curve"):
        raise RuntimeError("the installed libzmq/PyZMQ build does not support CURVE")
    if auth_config is None:
        auth_config = _load_curve_config_from_env(my_id)
    if not isinstance(auth_config, dict):
        raise ValueError(
            "ZMQ_AUTH_MODE=curve requires authenticated-channel configuration; "
            f"pass auth_config or set {CURVE_CONFIG_DIR_ENV}"
        )
    if not isinstance(my_id, int) or not 0 <= my_id < len(peers_config):
        raise ValueError("transport party ID must index peers_config")

    required = (
        CURVE_PUBLIC_KEY,
        CURVE_SECRET_KEY,
        CURVE_PUBLIC_KEYS,
        CURVE_ZAP_DOMAIN,
        CURVE_RUN_ID,
    )
    missing = [name for name in required if name not in auth_config]
    if missing:
        raise ValueError(
            "missing CURVE configuration field(s): " + ", ".join(sorted(missing))
        )

    public_key = _validated_z85_key(CURVE_PUBLIC_KEY, auth_config[CURVE_PUBLIC_KEY])
    secret_key = _validated_z85_key(CURVE_SECRET_KEY, auth_config[CURVE_SECRET_KEY])
    registry_values = auth_config[CURVE_PUBLIC_KEYS]
    if not isinstance(registry_values, list):
        raise ValueError(f"{CURVE_PUBLIC_KEYS} must be an ordered list")
    if len(registry_values) != len(peers_config):
        raise ValueError(
            f"{CURVE_PUBLIC_KEYS} has {len(registry_values)} entries; "
            f"expected {len(peers_config)} (one per global transport identity)"
        )
    registry = tuple(
        _validated_z85_key(f"{CURVE_PUBLIC_KEYS}[{party_id}]", value)
        for party_id, value in enumerate(registry_values)
    )
    if len(set(registry)) != len(registry):
        raise ValueError(f"{CURVE_PUBLIC_KEYS} contains duplicate public keys")
    if public_key != registry[my_id]:
        raise ValueError(
            f"{CURVE_PUBLIC_KEY} does not match {CURVE_PUBLIC_KEYS}[{my_id}]"
        )
    if zmq.curve_public(secret_key) != public_key:
        raise ValueError(f"{CURVE_SECRET_KEY} does not match {CURVE_PUBLIC_KEY}")

    domain = auth_config[CURVE_ZAP_DOMAIN]
    if not isinstance(domain, str) or not domain:
        raise ValueError(f"{CURVE_ZAP_DOMAIN} must be a non-empty string")
    domain_bytes = domain.encode("utf-8")
    run_id = auth_config[CURVE_RUN_ID]
    if not isinstance(run_id, str) or not run_id:
        raise ValueError(f"{CURVE_RUN_ID} must be a non-empty string")

    return {
        "public_key": public_key,
        "secret_key": secret_key,
        "public_keys": registry,
        "party_by_user_id": {key: party_id for party_id, key in enumerate(registry)},
        "zap_domain": domain,
        "zap_domain_bytes": domain_bytes,
        "run_id": run_id,
    }


class CurveCredentialsProvider(object):
    def __init__(self, domain, allowed_keys):
        self.domain = domain
        self.allowed_keys = frozenset(allowed_keys)
        self.denied_count = 0

    def callback(self, domain, client_key):
        allowed = domain == self.domain and client_key in self.allowed_keys
        if not allowed:
            self.denied_count += 1
            fingerprint = hashlib.sha256(client_key).hexdigest()[:12]
            logging.warning(
                "Rejected CURVE client authentication: domain=%r key_fingerprint=%s",
                domain,
                fingerprint,
            )
        return allowed


class NodeCommunicator(object):
    LAST_MSG = None

    def __init__(
        self,
        peers_config,
        my_id,
        linger_timeout=10,
        auth_mode=None,
        auth_config=None,
        readiness_barrier=True,
        readiness_timeout=None,
        metrics_context=None,
        metrics_enabled=None,
        metrics_output_dir=None,
    ):
        self.peers_config = peers_config
        self.my_id = my_id
        self.auth_mode = resolve_auth_mode(auth_mode)
        if not isinstance(readiness_barrier, bool):
            raise ValueError("readiness_barrier must be a boolean")
        self.readiness_barrier = readiness_barrier
        self.readiness_timeout = None
        if self.auth_mode == AUTH_MODE_CURVE and self.readiness_barrier:
            self.readiness_timeout = resolve_readiness_timeout(readiness_timeout)
        self.curve_config = None
        if self.auth_mode == AUTH_MODE_CURVE:
            self.curve_config = validate_curve_config(peers_config, my_id, auth_config)

        self.bytes_sent = 0
        self.bytes_count = defaultdict(lambda:0)
        self.message_count = defaultdict(lambda:0)
        self.communication_metrics = CommunicationMetricsArtifact(
            metrics_context,
            enabled=metrics_enabled,
            output_dir=metrics_output_dir,
        )
        self.benchmark_logger = logging.LoggerAdapter(
            logging.getLogger("benchmark_logger"), {"node_id": my_id}
        )

        self._dealer_tasks = []
        self._router_task = None
        self._authenticator = None
        self._curve_credentials = None
        self.invalid_auth_metadata_count = 0
        self.identity_spoofing_count = 0
        self.channel_setup_ms = None
        self._readiness_expected = set(range(len(peers_config))) - {self.my_id}
        self._readiness_pings = set()
        self._readiness_acks = set()
        self._readiness_event = asyncio.Event()
        self.linger_timeout = linger_timeout
        max_sockets = resolve_max_sockets(len(peers_config))
        io_threads = resolve_io_threads()
        self.zmq_context = Context(io_threads=io_threads)
        self.zmq_context.max_sockets = max_sockets
        self.benchmark_logger.info(
            "ZeroMQ context max_sockets: %d for %d peers; io_threads: %d",
            max_sockets,
            len(peers_config),
            io_threads,
        )

        n = len(peers_config)
        self._receiver_queue = asyncio.Queue()
        self._sender_queues = [None] * n
        for i in range(n):
            if i == self.my_id:
                self._sender_queues[i] = self._receiver_queue
            else:
                self._sender_queues[i] = asyncio.Queue()

    def send(self, node_id, msg):
        msg = (self.my_id, msg) if node_id == self.my_id else msg
        self._sender_queues[node_id].put_nowait(msg)

    async def recv(self):
        return await self._receiver_queue.get()

    def write_metrics_checkpoint(self):
        """Persist protocol-complete metrics before a global exit barrier."""
        return self.communication_metrics.write(
            self.snapshot_communication_metrics(),
            {
                "auth_mode": self.auth_mode,
                "drained_on_exit": False,
                "channel_setup_ms": self.channel_setup_ms,
            },
            completed=True,
            artifact_state="protocol-complete-checkpoint",
        )

    async def __aenter__(self):
        try:
            await self._setup()
        except BaseException:
            await self._abort_setup()
            raise
        return self

    async def __aexit__(self, exc_type, exc, tb):
        # Add None to the sender queues and drain out all the messages.
        for i in range(len(self._sender_queues)):
            if i != self.my_id:
                self._sender_queues[i].put_nowait(NodeCommunicator.LAST_MSG)
        await asyncio.gather(*self._dealer_tasks)
        if self._router_task is not None:
            self._router_task.cancel()
            await asyncio.gather(self._router_task, return_exceptions=True)
        try:
            self._stop_authenticator()
        finally:
            self.zmq_context.destroy(linger=self.linger_timeout * 1000)
        self.communication_metrics.write(
            self.snapshot_communication_metrics(),
            {
                "auth_mode": self.auth_mode,
                "drained_on_exit": True,
                "channel_setup_ms": self.channel_setup_ms,
            },
            completed=exc_type is None,
        )
        # self.benchmark_logger.info("Total bytes sent out: %d", self.bytes_sent)
        # for k,v in self.bytes_count.items():
            # print(f"[{self.my_id}] Bytes Sent: {k}:{v}, {round((100*v)/self.bytes_sent,2)}%")

    async def _abort_setup(self):
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
        self.zmq_context.destroy(linger=0)

    def _stop_authenticator(self):
        if self._authenticator is not None:
            self._authenticator.stop()
            self._authenticator = None

    def _start_curve_authenticator(self):
        self._curve_credentials = CurveCredentialsProvider(
            self.curve_config["zap_domain"], self.curve_config["public_keys"]
        )
        self._authenticator = AsyncioAuthenticator(self.zmq_context)
        self._authenticator.start()
        self._authenticator.configure_curve_callback(
            domain=self.curve_config["zap_domain"],
            credentials_provider=self._curve_credentials,
        )

    def _configure_curve_server(self, router):
        router.curve_publickey = self.curve_config["public_key"]
        router.curve_secretkey = self.curve_config["secret_key"]
        router.curve_server = True
        router.zap_domain = self.curve_config["zap_domain_bytes"]

    def _configure_curve_client(self, dealer, peer_id):
        dealer.curve_publickey = self.curve_config["public_key"]
        dealer.curve_secretkey = self.curve_config["secret_key"]
        dealer.curve_serverkey = self.curve_config["public_keys"][peer_id]

    def _channel_control_message(self, kind):
        return (CHANNEL_CONTROL_MARKER, self.curve_config["run_id"], kind)

    @staticmethod
    def _is_channel_control_message(msg):
        return (
            isinstance(msg, tuple)
            and len(msg) == 3
            and msg[0] == CHANNEL_CONTROL_MARKER
            and msg[2] in (CHANNEL_CONTROL_PING, CHANNEL_CONTROL_ACK)
        )

    @staticmethod
    def _application_message_type(msg):
        """Return the full outer application tag, unwrapping empty runner tags."""
        current = msg
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

    def snapshot_communication_metrics(self):
        tags = {}
        for tag in sorted(set(self.bytes_count) | set(self.message_count)):
            tags[tag] = {
                "bytes": int(self.bytes_count[tag]),
                "messages": int(self.message_count[tag]),
            }
        return {
            "scope": "serialized application-payload bytes sent to remote parties",
            "self_send_included": False,
            "curve_control_included": False,
            "total_remote_payload_bytes": int(self.bytes_sent),
            "total_remote_messages": int(sum(self.message_count.values())),
            "by_tag": tags,
        }

    def register_protocol_batch(self, **entry):
        self.communication_metrics.register_batch(**entry)

    def record_proof_quorum(self, **entry):
        self.communication_metrics.record_proof_quorum(entry)

    def _handle_channel_control(self, sender_id, msg):
        if not self._is_channel_control_message(msg):
            return False
        if msg[1] != self.curve_config["run_id"]:
            logging.warning(
                "Dropping CURVE readiness message with mismatched run_id from %d",
                sender_id,
            )
            return True
        if msg[2] == CHANNEL_CONTROL_PING:
            self._readiness_pings.add(sender_id)
            self.send(sender_id, self._channel_control_message(CHANNEL_CONTROL_ACK))
        else:
            self._readiness_acks.add(sender_id)
        if (
            self._readiness_expected <= self._readiness_pings
            and self._readiness_expected <= self._readiness_acks
        ):
            self._readiness_event.set()
        return True

    async def _wait_for_curve_readiness(self):
        if not self._readiness_expected:
            self._readiness_event.set()
            return
        ping = self._channel_control_message(CHANNEL_CONTROL_PING)
        for peer_id in sorted(self._readiness_expected):
            self.send(peer_id, ping)
        try:
            await asyncio.wait_for(
                self._readiness_event.wait(), timeout=self.readiness_timeout
            )
        except asyncio.TimeoutError as exc:
            missing_pings = sorted(self._readiness_expected - self._readiness_pings)
            missing_acks = sorted(self._readiness_expected - self._readiness_acks)
            raise RuntimeError(
                "CURVE readiness timed out after "
                f"{self.readiness_timeout:.3f}s; missing authenticated pings from "
                f"{missing_pings}; missing acknowledgements from {missing_acks}"
            ) from exc

    async def _setup(self):
        setup_started = time.perf_counter()
        if self.auth_mode == AUTH_MODE_CURVE:
            self._start_curve_authenticator()
        # Setup one router for a party, this acts as a
        # server for receiving messages from other parties.
        router = self.zmq_context.socket(ROUTER)
        if self.auth_mode == AUTH_MODE_CURVE:
            self._configure_curve_server(router)
        router.bind(f"tcp://*:{self.peers_config[self.my_id].port}")
        # Start a task to receive messages on this node.
        self._router_task = asyncio.create_task(self._recv_loop(router))
        self._router_task.add_done_callback(print_exception_callback)

        # Setup one dealer per receving party. This is used
        # as a client to send messages to other parties.
        for i in range(len(self.peers_config)):
            if i != self.my_id:
                dealer = self.zmq_context.socket(DEALER)
                if self.auth_mode == AUTH_MODE_CURVE:
                    self._configure_curve_client(dealer, i)
                # This identity is sent with each message. Setting it to my_id, this is
                # used to appropriately route the message. This is not a good idea since
                # a node can pretend to send messages on behalf of other nodes.
                dealer.setsockopt(IDENTITY, str(self.my_id).encode())
                dealer.connect(
                    f"tcp://{self.peers_config[i].ip}:{self.peers_config[i].port}"
                )
                # Setup a task which reads messages intended for this
                # party from a queue and then sends them to this node.
                task = asyncio.create_task(
                    self._process_node_messages(
                        i, self._sender_queues[i], dealer.send_multipart
                    )
                )
                self._dealer_tasks.append(task)

        if self.auth_mode == AUTH_MODE_CURVE and self.readiness_barrier:
            await self._wait_for_curve_readiness()
            self.channel_setup_ms = (time.perf_counter() - setup_started) * 1000
            print(
                f"my_send_id: {self.my_id} CURVE channel_setup_ms: "
                f"{self.channel_setup_ms:.3f}"
            )

    async def _recv_loop(self, router):
        while True:
            if self.auth_mode == AUTH_MODE_NULL:
                sender_id, raw_msg = await router.recv_multipart()
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
                authenticated_sender = self.curve_config["party_by_user_id"].get(user_id)
                if authenticated_sender is None:
                    self.invalid_auth_metadata_count += 1
                    logging.warning("Dropping CURVE message with unmapped User-Id")
                    continue
                expected_routing_id = str(authenticated_sender).encode("ascii")
                if bytes(routing_frame) != expected_routing_id:
                    self.identity_spoofing_count += 1
                    logging.warning(
                        "Dropping CURVE identity spoof: authenticated_sender=%d",
                        authenticated_sender,
                    )
                    continue
                sender_id = authenticated_sender
                raw_msg = bytes(payload_frame)
            msg = loads(raw_msg)
            if (
                self.auth_mode == AUTH_MODE_CURVE
                and self._handle_channel_control(int(sender_id), msg)
            ):
                continue
            # logging.debug("[RECV] FROM: %s, MSG: %s,", sender_id, msg)
            self._receiver_queue.put_nowait((int(sender_id), msg))

    async def _process_node_messages(self, node_id, node_msg_queue, send_to_node):
        while True:
            msg = await node_msg_queue.get()
            if msg is NodeCommunicator.LAST_MSG:
                logging.debug("No more messages to Node: %d can be sent.", node_id)
                break
            raw_msg = dumps(msg)
            if not self._is_channel_control_message(msg):
                self.bytes_sent += len(raw_msg)
                # logging.info("[SEND] TO: %d, MSG_TYPE: %s", node_id, msg[1][0])
                msg_type = self._application_message_type(msg)
                self.bytes_count[msg_type] = self.bytes_count[msg_type] + len(raw_msg)
                self.message_count[msg_type] = self.message_count[msg_type] + 1
            await send_to_node([raw_msg])


class ProcessProgramRunner(object):
    def __init__(
        self,
        peers_config,
        n,
        t,
        my_id,
        mpc_config=None,
        linger_timeout=2,
        auth_mode=None,
        auth_config=None,
        readiness_barrier=True,
        readiness_timeout=None,
        metrics_context=None,
        metrics_enabled=None,
        metrics_output_dir=None,
    ):
        self.peers_config = peers_config
        self.n = n
        self.t = t
        self.my_id = my_id
        self.mpc_config = {} if mpc_config is None else mpc_config
        self.mpc_config[ConfigVars.Reconstruction] = HbmpcConfig.reconstruction

        # Distributed entry points already load per-party material into
        # HbmpcConfig.extras; local multi-process runs use the directory fallback.
        if auth_config is None:
            auth_config = HbmpcConfig.extras

        self.node_communicator = NodeCommunicator(
            peers_config,
            my_id,
            linger_timeout,
            auth_mode=auth_mode,
            auth_config=auth_config,
            readiness_barrier=readiness_barrier,
            readiness_timeout=readiness_timeout,
            metrics_context=metrics_context,
            metrics_enabled=metrics_enabled,
            metrics_output_dir=metrics_output_dir,
        )
        self.progs = []

    def execute(self, sid, program, **kwargs):
        send, recv = self.get_send_recv(sid)
        context = Mpc(
            sid,
            self.n,
            self.t,
            self.my_id,
            send,
            recv,
            program,
            self.mpc_config,
            **kwargs,
        )
        program_result = asyncio.Future()

        def callback(future):
            program_result.set_result(future.result())

        task = asyncio.create_task(context._run())
        task.add_done_callback(callback)
        task.add_done_callback(print_exception_callback)
        self.progs.append(task)
        return program_result

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
        await asyncio.gather(*self.progs)
        await self.node_communicator.__aexit__(exc_type, exc, tb)
        self.subscribe_task.cancel()


async def verify_all_connections(peers, n, my_id):
    # Uncomment this if you want to test on multiple processes.
    # No need to uncomment this when running across servers
    # since the network latency is already present there.

    # logging.debug("Sleeping for: %d", my_id)
    # await asyncio.sleep(my_id)

    async with NodeCommunicator(peers, my_id) as node_communicator:
        for i in range(n):
            node_communicator.send(i, i)
        sender_ids = set()
        keys = set()
        for i in range(n):
            msg = await node_communicator.recv()
            sender_ids.add(msg[0])
            keys.add(msg[1])
        assert len(sender_ids) == n
        for i in range(n):
            assert i in sender_ids
        assert len(keys) == 1
        assert keys.pop() == my_id
        logging.info("Verfification completed.")


async def test_mpc_programs(peers, n, t, my_id):
    from adkg.mpc import test_prog1, test_prog2, test_batchopening
    from adkg.preprocessing import PreProcessedElements
    from adkg.preprocessing import wait_for_preprocessing, preprocessing_done

    if not HbmpcConfig.skip_preprocessing:
        # Only one party needs to generate the preprocessed elements for testing
        if HbmpcConfig.my_id == 0:
            pp_elements = PreProcessedElements()
            pp_elements.generate_zeros(1000, HbmpcConfig.N, HbmpcConfig.t)
            pp_elements.generate_triples(1000, HbmpcConfig.N, HbmpcConfig.t)
            preprocessing_done()
        else:
            await wait_for_preprocessing()

    async with ProcessProgramRunner(peers, n, t, my_id) as runner:
        test_prog1  # r1 = runner.execute("0", test_prog1)
        r2 = runner.execute("1", test_prog2)
        r3 = runner.execute("2", test_batchopening)
        results = await asyncio.gather(*[r2, r3])
        return results


if __name__ == "__main__":
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    # loop.run_until_complete(
    #     verify_all_connections(HbmpcConfig.peers, HbmpcConfig.N, HbmpcConfig.my_id))
    loop.run_until_complete(
        test_mpc_programs(
            HbmpcConfig.peers, HbmpcConfig.N, HbmpcConfig.t, HbmpcConfig.my_id
        )
    )
