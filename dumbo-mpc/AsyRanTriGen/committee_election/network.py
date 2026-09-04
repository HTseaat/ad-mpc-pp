"""Authenticated-network adapter shared by standalone and Continuum elections."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import time
from typing import Any, Awaitable, Callable, Dict, Mapping, Sequence

from .crypto import ElectionCertificate
from .model import CandidateRegistry, ElectionContext
from .protocol import (
    ElectionNode,
    ElectionProtocolError,
    ElectionTimeout,
    NodeResult,
    ShareEnvelope,
)


METRICS_SCHEMA_VERSION = 1
Send = Callable[[int, Any], None]
Recv = Callable[[], Awaitable[Any]]


@dataclass(frozen=True)
class NetworkElectionResult:
    node_result: NodeResult
    network_wait_ms: float
    messages_sent_remote: int

    def metrics_dict(
        self,
        *,
        n: int,
        t: int,
        registry: CandidateRegistry,
        context: ElectionContext,
        bytes_sent_remote: int,
        channel_setup_ms: float,
    ) -> Dict[str, Any]:
        node = self.node_result
        metrics = node.metrics
        certificate = node.certificate
        return {
            "K": len(registry.candidates),
            "bytes_sent_remote": bytes_sent_remote,
            "candidate_index": certificate.candidate_index,
            "certificate_verify_ms": metrics.certificate_verify_ms,
            "channel_setup_ms": channel_setup_ms,
            "combine_ms": metrics.combine_ms,
            "committee_id": certificate.committee_id,
            "election_total_ms": metrics.election_total_ms,
            "invalid_shares_rejected": sum(metrics.rejection_counts.values()),
            "messages_sent_remote": self.messages_sent_remote,
            "metrics_schema_version": METRICS_SCHEMA_VERSION,
            "n": n,
            "network_wait_ms": self.network_wait_ms,
            "node_id": node.node_id,
            "registry_digest": context.registry_digest,
            "rejection_counts": dict(metrics.rejection_counts),
            "run_id": context.run_id,
            "selection_ms": metrics.selection_ms,
            "share_verify_ms_total": metrics.share_verify_ms_total,
            "sign_ms": metrics.sign_ms,
            "signature_digest": certificate.signature_digest,
            "source_committee_id": context.source_committee_id,
            "t": t,
            "target_epoch": context.target_epoch,
            "used_share_ids": list(metrics.used_share_ids),
            "valid_shares_received": len(metrics.accepted_share_ids),
        }


async def run_network_election(
    *,
    local_id: int,
    public_key: Any,
    private_key: Any,
    registry: CandidateRegistry,
    context: ElectionContext,
    participant_global_ids: Sequence[int],
    send: Send,
    recv: Recv,
    omit_share: bool = False,
    timeout: float = 30.0,
) -> NetworkElectionResult:
    """Run one TBLS election over an already authenticated tagged channel."""

    participant_global_ids = tuple(participant_global_ids)
    if len(participant_global_ids) != public_key.l:
        raise ElectionProtocolError("participant mapping does not match TBLS party count")
    if len(set(participant_global_ids)) != len(participant_global_ids):
        raise ElectionProtocolError("participant global IDs must be unique")
    if type(local_id) is not int or not 0 <= local_id < public_key.l:
        raise ElectionProtocolError("local election ID is out of range")
    global_to_local = {
        global_id: mapped_local_id
        for mapped_local_id, global_id in enumerate(participant_global_ids)
    }
    node = ElectionNode(
        node_id=local_id,
        public_key=public_key,
        private_key=private_key,
        registry=registry,
        context=context,
    )
    started_at = time.perf_counter()
    envelope = node.create_envelope()
    messages_sent_remote = 0
    if not omit_share:
        payload = envelope.to_dict()
        own_global_id = participant_global_ids[local_id]
        for destination in participant_global_ids:
            send(destination, payload)
            if destination != own_global_id:
                messages_sent_remote += 1

    network_wait_ms = 0.0

    async def collect() -> NodeResult:
        nonlocal network_wait_ms
        while not node.certificate_ready:
            wait_started = time.perf_counter()
            transport_sender_id, payload = await recv()
            network_wait_ms += (time.perf_counter() - wait_started) * 1000.0
            local_sender_id = global_to_local.get(transport_sender_id)
            if local_sender_id is None:
                node.rejections["sender_out_of_committee"] += 1
                continue
            try:
                received_envelope = ShareEnvelope.from_dict(payload)
            except ElectionProtocolError:
                node.rejections["malformed_envelope"] += 1
                continue
            node.receive(local_sender_id, received_envelope)
        return node.result(started_at)

    try:
        node_result = await asyncio.wait_for(collect(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ElectionTimeout(
            f"network election for target epoch {context.target_epoch} timed out"
        ) from exc
    return NetworkElectionResult(
        node_result=node_result,
        network_wait_ms=network_wait_ms,
        messages_sent_remote=messages_sent_remote,
    )


def certificate_payload(certificate: ElectionCertificate) -> Mapping[str, Any]:
    return certificate.to_dict()
