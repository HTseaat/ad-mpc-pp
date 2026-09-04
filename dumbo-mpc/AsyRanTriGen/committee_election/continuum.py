"""Shadow lookahead and strictly sequential gated election for Continuum."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
import time
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .crypto import ElectionCertificate, verify_certificate
from .model import CandidateRegistry, ElectionContext
from .network import NetworkElectionResult, run_network_election


VALID_PIPELINE_MODES = frozenset(("off", "shadow", "gated"))
PIPELINE_ELECTION_MARKER = "COMMITTEE_ELECTION_PIPELINE "
PIPELINE_GATE_MARKER = "COMMITTEE_ELECTION_GATE "


class ContinuumElectionError(RuntimeError):
    pass


def resolve_pipeline_mode(value=None):
    raw = os.getenv("COMMITTEE_ELECTION_MODE", "off") if value is None else value
    if not isinstance(raw, str):
        raise ContinuumElectionError("committee-election mode must be text")
    mode = raw.strip().lower()
    if mode not in VALID_PIPELINE_MODES:
        raise ContinuumElectionError(
            "committee-election mode must be off, shadow, or gated"
        )
    return mode


@dataclass(frozen=True)
class CertificateArrival:
    certificate: ElectionCertificate
    election_started_unix_ms: float
    certificate_ready_unix_ms: float


class ContinuumElectionPipeline:
    def __init__(
        self,
        *,
        mode: str,
        n: int,
        t: int,
        layers: int,
        physical_layer_id: int,
        local_id: int,
        public_key: Any,
        private_key: Any,
        all_public_keys: Sequence[Any],
        registry: CandidateRegistry,
        run_id: str,
        get_send,
        subscribe_recv,
    ):
        self.mode = resolve_pipeline_mode(mode)
        if self.mode == "off":
            raise ContinuumElectionError("off mode must not create a pipeline object")
        if n < 3 * t + 1 or public_key.l != n or public_key.k != t + 1:
            raise ContinuumElectionError("election key/config does not match n and t")
        if len(all_public_keys) != layers:
            raise ContinuumElectionError("one election public key is required per layer")
        if not 0 <= physical_layer_id < layers:
            raise ContinuumElectionError("physical layer is out of range")
        if not 0 <= local_id < n:
            raise ContinuumElectionError("local party is out of range")
        self.n = n
        self.t = t
        self.layers = layers
        self.physical_layer_id = physical_layer_id
        self.local_id = local_id
        self.public_key = public_key
        self.private_key = private_key
        self.all_public_keys = tuple(all_public_keys)
        self.registry = registry
        self.run_id = run_id
        self.get_send = get_send
        self.subscribe_recv = subscribe_recv
        self.timeout = float(os.getenv("COMMITTEE_ELECTION_TIMEOUT_SECONDS", "30"))
        if self.timeout <= 0:
            raise ContinuumElectionError("committee-election timeout must be positive")
        self._required_task = None
        self._lookahead_task = None
        self._handoff_ready_unix_ms = None
        self._handoff_start_unix_ms = None
        self._certificate_ready_at_handoff = None

    def _share_tag(self, target_epoch):
        return f"CE:share:{self.physical_layer_id}:{target_epoch}"

    @staticmethod
    def _certificate_tag(target_epoch):
        return f"CE:certificate:{target_epoch}"

    def _context(self, source_layer, target_epoch):
        return ElectionContext.for_registry(
            run_id=self.run_id,
            source_committee_id=f"P{source_layer}",
            target_epoch=target_epoch,
            registry=self.registry,
        )

    async def start(self):
        layer = self.physical_layer_id
        # Shadow mode retains the Stage-6 one-epoch-ahead observation path.
        # Gated mode is deliberately empty here: its source committee starts
        # and completes E(layer+1) only when that layer is ready to hand off.
        if self.mode == "shadow" and 2 <= layer <= self.layers - 2:
            self._required_task = asyncio.create_task(
                self._receive_required_certificate(target_epoch=layer + 1)
            )

    async def _run_source_election(
        self, *, target_epoch: int, forward_to_layer: Optional[int]
    ) -> Tuple[NetworkElectionResult, CertificateArrival]:
        source_layer = self.physical_layer_id
        context = self._context(source_layer, target_epoch)
        send = self.get_send(self._share_tag(target_epoch))
        recv = self.subscribe_recv(self._share_tag(target_epoch))
        participants = tuple(
            source_layer * self.n + local_id for local_id in range(self.n)
        )
        election_started_unix_ms = time.time() * 1000.0
        result = await run_network_election(
            local_id=self.local_id,
            public_key=self.public_key,
            private_key=self.private_key,
            registry=self.registry,
            context=context,
            participant_global_ids=participants,
            send=send,
            recv=recv,
            timeout=self.timeout,
        )
        certificate_ready_unix_ms = time.time() * 1000.0
        arrival = CertificateArrival(
            certificate=result.node_result.certificate,
            election_started_unix_ms=election_started_unix_ms,
            certificate_ready_unix_ms=certificate_ready_unix_ms,
        )
        if forward_to_layer is not None:
            certificate_send = self.get_send(self._certificate_tag(target_epoch))
            payload = {
                "certificate": arrival.certificate.to_dict(),
                "certificate_ready_unix_ms": certificate_ready_unix_ms,
                "election_started_unix_ms": election_started_unix_ms,
            }
            for destination_local_id in range(self.n):
                certificate_send(
                    forward_to_layer * self.n + destination_local_id, payload
                )
        metrics = result.node_result.metrics
        record = {
            "candidate_index": arrival.certificate.candidate_index,
            "certificate_ready_unix_ms": certificate_ready_unix_ms,
            "committee_id": arrival.certificate.committee_id,
            "election_started_unix_ms": election_started_unix_ms,
            "election_total_ms": metrics.election_total_ms,
            "local_id": self.local_id,
            "mode": self.mode,
            "network_wait_ms": result.network_wait_ms,
            "physical_source_layer": source_layer,
            "registry_digest": context.registry_digest,
            "signature_digest": arrival.certificate.signature_digest,
            "target_epoch": target_epoch,
        }
        print(PIPELINE_ELECTION_MARKER + json.dumps(record, sort_keys=True), flush=True)
        return result, arrival

    async def _receive_required_certificate(self, *, target_epoch):
        receiver_layer = self.physical_layer_id
        source_layer = receiver_layer - 1
        recv = self.subscribe_recv(self._certificate_tag(target_epoch))
        valid_global_senders = set(
            range(source_layer * self.n, (source_layer + 1) * self.n)
        )

        async def receive():
            while True:
                transport_sender, payload = await recv()
                if transport_sender not in valid_global_senders:
                    continue
                if not isinstance(payload, Mapping) or set(payload) != {
                    "certificate",
                    "certificate_ready_unix_ms",
                    "election_started_unix_ms",
                }:
                    continue
                try:
                    certificate = ElectionCertificate.from_dict(payload["certificate"])
                    verify_certificate(
                        public_key=self.all_public_keys[source_layer],
                        registry=self.registry,
                        certificate=certificate,
                    )
                except Exception:
                    continue
                if (
                    certificate.target_epoch != target_epoch
                    or certificate.source_committee_id != f"P{source_layer}"
                ):
                    continue
                started = payload["election_started_unix_ms"]
                ready = payload["certificate_ready_unix_ms"]
                if (
                    isinstance(started, bool)
                    or not isinstance(started, (int, float))
                    or isinstance(ready, bool)
                    or not isinstance(ready, (int, float))
                    or ready < started
                ):
                    continue
                return CertificateArrival(certificate, float(started), float(ready))

        return await receive()

    async def before_handoff(self):
        layer = self.physical_layer_id
        if not 1 <= layer <= self.layers - 2:
            return
        self._handoff_ready_unix_ms = time.time() * 1000.0
        if self.mode == "gated":
            # Strict sequential ordering:
            #   local computation -> E(layer+1) -> handoff(layer, layer+1)
            # No election task overlaps this layer's Transfer/BatchMul handoff.
            self._required_task = asyncio.create_task(
                self._run_source_election(
                    target_epoch=layer + 1,
                    forward_to_layer=None,
                )
            )
            self._certificate_ready_at_handoff = self._required_task.done()
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._required_task), timeout=self.timeout
                )
            except asyncio.TimeoutError as exc:
                raise ContinuumElectionError(
                    f"sequential election timed out for target epoch {layer + 1}"
                ) from exc
            self._handoff_start_unix_ms = time.time() * 1000.0
            return

        # Stage-6 shadow mode keeps the original lookahead timing experiment.
        if layer == 1:
            self._required_task = asyncio.create_task(
                self._run_source_election(target_epoch=2, forward_to_layer=None)
            )
        if self._required_task is None:
            raise ContinuumElectionError("required election task was not initialized")
        self._certificate_ready_at_handoff = self._required_task.done()
        self._handoff_start_unix_ms = time.time() * 1000.0
        lookahead_target = layer + 2
        if lookahead_target <= self.layers - 1:
            self._lookahead_task = asyncio.create_task(
                self._run_source_election(
                    target_epoch=lookahead_target,
                    forward_to_layer=layer + 1,
                )
            )

    @staticmethod
    def _arrival_from_result(result):
        if isinstance(result, CertificateArrival):
            return result
        if (
            isinstance(result, tuple)
            and len(result) == 2
            and isinstance(result[1], CertificateArrival)
        ):
            return result[1]
        raise ContinuumElectionError("unexpected election task result")

    async def finalize(self):
        if self._lookahead_task is not None:
            await self._lookahead_task
        if self._required_task is None:
            return
        try:
            required_result = await asyncio.wait_for(
                asyncio.shield(self._required_task), timeout=self.timeout
            )
        except asyncio.TimeoutError as exc:
            raise ContinuumElectionError(
                f"pipeline finalization timed out at layer {self.physical_layer_id}"
            ) from exc
        required = self._arrival_from_result(required_result)
        if self._handoff_ready_unix_ms is None or self._handoff_start_unix_ms is None:
            raise ContinuumElectionError("handoff timing was not recorded")
        actual_wait_ms = 0.0
        if self.mode == "gated" and not self._certificate_ready_at_handoff:
            actual_wait_ms = max(
                0.0, self._handoff_start_unix_ms - self._handoff_ready_unix_ms
            )
        record: Dict[str, Any] = {
            "certificate_ready_unix_ms": required.certificate_ready_unix_ms,
            "election_deadline_missed": not self._certificate_ready_at_handoff,
            "election_started_unix_ms": required.election_started_unix_ms,
            "handoff_ready_unix_ms": self._handoff_ready_unix_ms,
            "handoff_start_unix_ms": self._handoff_start_unix_ms,
            "handoff_wait_ms": actual_wait_ms,
            "local_id": self.local_id,
            "mode": self.mode,
            "overlap_window_ms": max(
                0.0,
                self._handoff_ready_unix_ms
                - required.election_started_unix_ms,
            ),
            "physical_source_layer": self.physical_layer_id,
            "signature_digest": required.certificate.signature_digest,
            "target_epoch": self.physical_layer_id + 1,
            "would_block_ms": max(
                0.0,
                required.certificate_ready_unix_ms
                - self._handoff_ready_unix_ms,
            ),
        }
        print(PIPELINE_GATE_MARKER + json.dumps(record, sort_keys=True), flush=True)
