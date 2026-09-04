"""In-process asynchronous harness for committee-election Stages 1--3."""

from __future__ import annotations

import asyncio
import base64
from collections import Counter
from dataclasses import dataclass, field
import time
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .crypto import (
    CryptoBreakdown,
    ElectionCertificate,
    build_certificate,
    sign_share,
    verify_certificate,
    verify_share,
)
from .model import CandidateRegistry, ElectionContext


ENVELOPE_VERSION = 1


class ElectionProtocolError(RuntimeError):
    """Base class for in-process protocol failures."""


class InsufficientSharesError(ElectionProtocolError):
    """Raised when the simulated network closes below threshold."""


class ElectionTimeout(ElectionProtocolError):
    """Raised when the harness deadline expires; all tasks are then cancelled."""


@dataclass(frozen=True)
class ShareEnvelope:
    run_id: str
    source_committee_id: str
    target_epoch: int
    registry_digest: str
    sender_local_id: int
    signature_share_b64: str
    envelope_version: int = ENVELOPE_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_version": self.envelope_version,
            "registry_digest": self.registry_digest,
            "run_id": self.run_id,
            "sender_local_id": self.sender_local_id,
            "signature_share_b64": self.signature_share_b64,
            "source_committee_id": self.source_committee_id,
            "target_epoch": self.target_epoch,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ShareEnvelope":
        expected = {
            "envelope_version",
            "registry_digest",
            "run_id",
            "sender_local_id",
            "signature_share_b64",
            "source_committee_id",
            "target_epoch",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ElectionProtocolError("share envelope fields do not match schema")
        try:
            envelope = cls(**dict(value))
        except TypeError as exc:
            raise ElectionProtocolError("share envelope values do not match schema") from exc
        if (
            type(envelope.envelope_version) is not int
            or envelope.envelope_version != ENVELOPE_VERSION
            or type(envelope.sender_local_id) is not int
            or envelope.sender_local_id < 0
            or not isinstance(envelope.signature_share_b64, str)
        ):
            raise ElectionProtocolError("share envelope values are invalid")
        return envelope


def build_share_envelope(
    context: ElectionContext, sender_local_id: int, share_bytes: bytes
) -> ShareEnvelope:
    return ShareEnvelope(
        run_id=context.run_id,
        source_committee_id=context.source_committee_id,
        target_epoch=context.target_epoch,
        registry_digest=context.registry_digest,
        sender_local_id=sender_local_id,
        signature_share_b64=base64.b64encode(share_bytes).decode("ascii"),
    )


@dataclass(frozen=True)
class InjectedEnvelope:
    receiver_id: int
    transport_sender_id: int
    envelope: ShareEnvelope
    delay_ms: float = 0.0


@dataclass(frozen=True)
class FaultPlan:
    omitted_senders: Tuple[int, ...] = ()
    invalid_senders: Tuple[int, ...] = ()
    duplicate_senders: Tuple[int, ...] = ()
    delay_ms_by_sender: Mapping[int, float] = field(default_factory=dict)
    delivery_order_by_receiver: Mapping[int, Tuple[int, ...]] = field(
        default_factory=dict
    )
    injected_envelopes: Tuple[InjectedEnvelope, ...] = ()


@dataclass(frozen=True)
class NodeMetrics:
    sign_ms: float
    share_verify_ms_total: float
    combine_ms: float
    combined_verify_ms: float
    certificate_verify_ms: float
    selection_ms: float
    election_total_ms: float
    accepted_share_ids: Tuple[int, ...]
    used_share_ids: Tuple[int, ...]
    rejection_counts: Mapping[str, int]


@dataclass(frozen=True)
class NodeResult:
    node_id: int
    certificate: ElectionCertificate
    metrics: NodeMetrics


@dataclass(frozen=True)
class HarnessResult:
    nodes: Mapping[int, NodeResult]
    active_tasks_after: int

    @property
    def signature_digests(self) -> Tuple[str, ...]:
        return tuple(sorted({node.certificate.signature_digest for node in self.nodes.values()}))

    @property
    def committee_ids(self) -> Tuple[str, ...]:
        return tuple(sorted({node.certificate.committee_id for node in self.nodes.values()}))


class ElectionNode:
    def __init__(
        self,
        *,
        node_id: int,
        public_key: Any,
        private_key: Any,
        registry: CandidateRegistry,
        context: ElectionContext,
    ) -> None:
        self.node_id = node_id
        self.public_key = public_key
        self.private_key = private_key
        self.registry = registry
        self.context = context
        self.accepted: Dict[int, bytes] = {}
        self.rejections: Counter = Counter()
        self.sign_ms = 0.0
        self.verify_ms = 0.0
        self._certificate = None
        self._used_share_ids: Tuple[int, ...] = ()
        self._breakdown = CryptoBreakdown()
        self._certificate_verify_ms = 0.0
        self._certificate_ready_at = None

    @property
    def certificate_ready(self) -> bool:
        return self._certificate is not None

    def create_envelope(self, *, invalid: bool = False) -> ShareEnvelope:
        signing_context = self.context
        if invalid:
            signing_context = ElectionContext(
                run_id=self.context.run_id,
                source_committee_id=self.context.source_committee_id,
                target_epoch=self.context.target_epoch + 1000,
                registry_id=self.context.registry_id,
                registry_digest=self.context.registry_digest,
            )
        share, elapsed = sign_share(
            self.private_key, self.public_key, self.node_id, signing_context
        )
        self.sign_ms += elapsed
        return build_share_envelope(self.context, self.node_id, share)

    def _context_matches(self, envelope: ShareEnvelope) -> bool:
        return (
            envelope.envelope_version == ENVELOPE_VERSION
            and envelope.run_id == self.context.run_id
            and envelope.source_committee_id == self.context.source_committee_id
            and envelope.target_epoch == self.context.target_epoch
            and envelope.registry_digest == self.context.registry_digest
        )

    def receive(self, transport_sender_id: int, envelope: ShareEnvelope) -> None:
        if not isinstance(envelope, ShareEnvelope) or not self._context_matches(envelope):
            self.rejections["context_mismatch"] += 1
            return
        if transport_sender_id != envelope.sender_local_id:
            self.rejections["sender_mismatch"] += 1
            return
        if type(transport_sender_id) is not int or not 0 <= transport_sender_id < self.public_key.l:
            self.rejections["sender_out_of_range"] += 1
            return
        if transport_sender_id in self.accepted:
            self.rejections["duplicate_share"] += 1
            return
        try:
            share = base64.b64decode(
                envelope.signature_share_b64.encode("ascii"), validate=True
            )
        except Exception:
            self.rejections["malformed_share"] += 1
            return
        valid, elapsed = verify_share(
            self.public_key, transport_sender_id, self.context, share
        )
        self.verify_ms += elapsed
        if not valid:
            self.rejections["invalid_share"] += 1
            return
        self.accepted[transport_sender_id] = share
        if self._certificate is None and len(self.accepted) >= self.public_key.k:
            certificate, used_share_ids, breakdown = build_certificate(
                public_key=self.public_key,
                registry=self.registry,
                context=self.context,
                shares=self.accepted,
            )
            verify_started = time.perf_counter()
            verify_certificate(
                public_key=self.public_key,
                registry=self.registry,
                certificate=certificate,
            )
            self._certificate_verify_ms = (
                time.perf_counter() - verify_started
            ) * 1000.0
            self._certificate = certificate
            self._used_share_ids = used_share_ids
            self._breakdown = breakdown
            self._certificate_ready_at = time.perf_counter()

    def result(self, started_at: float) -> NodeResult:
        if self._certificate is None or self._certificate_ready_at is None:
            raise InsufficientSharesError(
                f"node {self.node_id} closed with {len(self.accepted)} valid shares"
            )
        return NodeResult(
            node_id=self.node_id,
            certificate=self._certificate,
            metrics=NodeMetrics(
                sign_ms=self.sign_ms,
                share_verify_ms_total=self.verify_ms
                + self._breakdown.share_verify_ms_total,
                combine_ms=self._breakdown.combine_ms,
                combined_verify_ms=self._breakdown.combined_verify_ms,
                certificate_verify_ms=self._certificate_verify_ms,
                selection_ms=self._breakdown.selection_ms,
                election_total_ms=(self._certificate_ready_at - started_at) * 1000.0,
                accepted_share_ids=tuple(sorted(self.accepted)),
                used_share_ids=self._used_share_ids,
                rejection_counts=dict(self.rejections),
            ),
        )

    async def collect(self, queue: "asyncio.Queue[Any]", started_at: float) -> NodeResult:
        while True:
            item = await queue.get()
            if item is None:
                break
            transport_sender_id, envelope = item
            self.receive(transport_sender_id, envelope)
        return self.result(started_at)


class InProcessElectionHarness:
    def __init__(
        self,
        *,
        n: int,
        t: int,
        public_key: Any,
        private_keys: Sequence[Any],
        registry: CandidateRegistry,
        context: ElectionContext,
    ) -> None:
        if len(private_keys) != n:
            raise ElectionProtocolError("one TBLS private share is required per node")
        if public_key.l != n or public_key.k != t + 1:
            raise ElectionProtocolError("TBLS public key does not match n/t")
        context.validate_registry(registry)
        self.n = n
        self.t = t
        self.public_key = public_key
        self.private_keys = tuple(private_keys)
        self.registry = registry
        self.context = context
        self.active_tasks_after = 0

    def _validate_fault_plan(self, plan: FaultPlan) -> None:
        for collection in (
            plan.omitted_senders,
            plan.invalid_senders,
            plan.duplicate_senders,
        ):
            if len(set(collection)) != len(collection):
                raise ElectionProtocolError("fault-plan sender IDs must be unique")
            if any(type(node) is not int or not 0 <= node < self.n for node in collection):
                raise ElectionProtocolError("fault-plan sender ID is out of range")
        for receiver, order in plan.delivery_order_by_receiver.items():
            if not 0 <= receiver < self.n or tuple(sorted(order)) != tuple(range(self.n)):
                raise ElectionProtocolError("delivery order must be a permutation of all nodes")
        for sender, delay in plan.delay_ms_by_sender.items():
            if not 0 <= sender < self.n or delay < 0:
                raise ElectionProtocolError("invalid sender delay")

    async def run(
        self, *, fault_plan: Optional[FaultPlan] = None, timeout: float = 2.0
    ) -> HarnessResult:
        plan = fault_plan or FaultPlan()
        self._validate_fault_plan(plan)
        tasks = []

        async def execute() -> HarnessResult:
            started_at = time.perf_counter()
            queues = [asyncio.Queue() for _ in range(self.n)]
            nodes = [
                ElectionNode(
                    node_id=node_id,
                    public_key=self.public_key,
                    private_key=self.private_keys[node_id],
                    registry=self.registry,
                    context=self.context,
                )
                for node_id in range(self.n)
            ]
            envelopes = {
                node.node_id: node.create_envelope(
                    invalid=node.node_id in plan.invalid_senders
                )
                for node in nodes
                if node.node_id not in plan.omitted_senders
            }

            async def deliver(
                receiver_id: int,
                transport_sender_id: int,
                envelope: ShareEnvelope,
                delay_ms: float,
            ) -> None:
                if delay_ms:
                    await asyncio.sleep(delay_ms / 1000.0)
                await queues[receiver_id].put((transport_sender_id, envelope))

            collectors = [
                asyncio.create_task(node.collect(queues[node.node_id], started_at))
                for node in nodes
            ]
            tasks.extend(collectors)
            delivery_tasks = []
            for receiver_id in range(self.n):
                order = plan.delivery_order_by_receiver.get(
                    receiver_id, tuple(range(self.n))
                )
                for position, sender_id in enumerate(order):
                    if sender_id not in envelopes:
                        continue
                    delay = float(plan.delay_ms_by_sender.get(sender_id, 0.0))
                    delay += position * 0.01
                    delivery_tasks.append(
                        asyncio.create_task(
                            deliver(receiver_id, sender_id, envelopes[sender_id], delay)
                        )
                    )
                    if sender_id in plan.duplicate_senders:
                        delivery_tasks.append(
                            asyncio.create_task(
                                deliver(
                                    receiver_id,
                                    sender_id,
                                    envelopes[sender_id],
                                    delay + 0.001,
                                )
                            )
                        )
            for injected in plan.injected_envelopes:
                if not 0 <= injected.receiver_id < self.n:
                    raise ElectionProtocolError("injected receiver is out of range")
                delivery_tasks.append(
                    asyncio.create_task(
                        deliver(
                            injected.receiver_id,
                            injected.transport_sender_id,
                            injected.envelope,
                            injected.delay_ms,
                        )
                    )
                )
            tasks.extend(delivery_tasks)
            await asyncio.gather(*delivery_tasks)
            for queue in queues:
                await queue.put(None)
            node_results = await asyncio.gather(*collectors)
            result = HarnessResult(
                nodes={result.node_id: result for result in node_results},
                active_tasks_after=0,
            )
            if len(result.signature_digests) != 1 or len(result.committee_ids) != 1:
                raise ElectionProtocolError("honest nodes disagreed on election result")
            return result

        try:
            result = await asyncio.wait_for(execute(), timeout=timeout)
            self.active_tasks_after = sum(not task.done() for task in tasks)
            return result
        except asyncio.TimeoutError as exc:
            raise ElectionTimeout("in-process election exceeded its deadline") from exc
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self.active_tasks_after = sum(not task.done() for task in tasks)
