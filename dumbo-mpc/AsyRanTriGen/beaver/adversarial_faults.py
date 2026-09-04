"""Opt-in fault configuration for the Continuum adversarial experiments.

The default configuration is a strict no-op.  Supported experiments are:

* fixed-delay handoff contributions from the last ``t`` local dealers; and
* an AggTrans commitment fork from those same dealers.  The fork is locally
  valid but carries a prior-epoch commitment vector that cannot obtain the
  ``n-t`` matching commitments required by Algorithm 1 line 207; and
* a BatchMul input-commitment fork that remains locally product-consistent but
  cannot obtain the matching input commitments required by Algorithm 2 line
  206.

The formal Figure 10 profile composes these hooks at source epochs 3/4/5 and
fixes the handoff delay at 10,000 ms.  The legacy single-component profiles
remain available for focused smoke tests.

Agreement traffic and the transport layer are deliberately left untouched.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import logging
import os
import time
from typing import Mapping, Optional, Sequence, Tuple


FAULT_EVENT_PREFIX = "FAULT_EVENT "
BYZANTINE_DELTA = 1
_LOG = logging.getLogger("fault_injection")


class FaultConfigurationError(ValueError):
    """Raised before protocol execution when fault settings are ambiguous."""


def _required_int(environ: Mapping[str, str], name: str) -> int:
    raw = environ.get(name, "").strip()
    if not raw:
        raise FaultConfigurationError(f"{name} is required")
    try:
        return int(raw)
    except ValueError as exc:
        raise FaultConfigurationError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class FaultConfig:
    mode: str
    target: Optional[str]
    computation_epoch: Optional[int]
    delta_ms: Optional[int]
    attack_index: Optional[int]
    selected_local_ids: Tuple[int, ...]
    batchmul_epoch: Optional[int] = None
    figure10_delay_epoch: Optional[int] = None
    figure10_aggtrans_epoch: Optional[int] = None
    figure10_batchmul_epoch: Optional[int] = None

    @property
    def enabled(self) -> bool:
        return self.mode != "none"

    @property
    def delay_source_epoch(self) -> Optional[int]:
        if self.mode == "delay":
            return self.computation_epoch
        if self.mode == "figure10-attack":
            return self.figure10_delay_epoch
        return None

    @property
    def aggtrans_source_epoch(self) -> Optional[int]:
        if self.mode == "byzantine" and self.target in {
            "aggtrans",
            "aggtrans+batchmul",
        }:
            return self.computation_epoch
        if self.mode == "figure10-attack":
            return self.figure10_aggtrans_epoch
        return None

    @property
    def batchmul_source_epoch(self) -> Optional[int]:
        if self.mode == "byzantine" and self.target in {
            "batchmul",
            "aggtrans+batchmul",
        }:
            return (
                self.batchmul_epoch
                if self.target == "aggtrans+batchmul"
                else self.computation_epoch
            )
        if self.mode == "figure10-attack":
            return self.figure10_batchmul_epoch
        return None

    @classmethod
    def from_env(
        cls,
        *,
        n: int,
        t: int,
        layers: int,
        environ: Optional[Mapping[str, str]] = None,
    ) -> "FaultConfig":
        env = os.environ if environ is None else environ
        mode = env.get("FAULT_MODE", "none").strip().lower() or "none"
        selected = tuple(range(n - t, n))

        if n < 3 * t + 1:
            raise FaultConfigurationError("n must satisfy n >= 3*t+1")
        if layers < 3:
            raise FaultConfigurationError("layers must include input, computation, and output")

        controlled_names = (
            "FAULT_TARGET",
            "FAULT_COMPUTATION_EPOCH",
            "FAULT_BATCHMUL_EPOCH",
            "FAULT_DELAY_SOURCE_EPOCH",
            "FAULT_AGGTRANS_SOURCE_EPOCH",
            "FAULT_BATCHMUL_SOURCE_EPOCH",
            "FAULT_DELTA_MS",
            "FAULT_ATTACK_INDEX",
        )

        if mode == "none":
            stale = [name for name in controlled_names if env.get(name, "").strip()]
            if stale:
                raise FaultConfigurationError(
                    "fault parameters require FAULT_MODE to be enabled: " + ", ".join(stale)
                )
            return cls("none", None, None, None, None, selected)

        if mode not in {"delay", "byzantine", "figure10-attack"}:
            raise FaultConfigurationError(
                f"unsupported FAULT_MODE={mode!r}; expected none, delay, "
                "byzantine, or figure10-attack"
            )

        target = env.get("FAULT_TARGET", "").strip().lower()
        max_epoch = layers - 2
        if mode == "figure10-attack":
            if target != "handoff+aggtrans+batchmul":
                raise FaultConfigurationError(
                    "FAULT_MODE=figure10-attack requires "
                    "FAULT_TARGET=handoff+aggtrans+batchmul"
                )
            stale_legacy = [
                name
                for name in ("FAULT_COMPUTATION_EPOCH", "FAULT_BATCHMUL_EPOCH")
                if env.get(name, "").strip()
            ]
            if stale_legacy:
                raise FaultConfigurationError(
                    "Figure 10 uses explicit source epochs, not legacy epoch fields: "
                    + ", ".join(stale_legacy)
                )
            delay_epoch = _required_int(env, "FAULT_DELAY_SOURCE_EPOCH")
            aggtrans_epoch = _required_int(env, "FAULT_AGGTRANS_SOURCE_EPOCH")
            batchmul_source_epoch = _required_int(
                env, "FAULT_BATCHMUL_SOURCE_EPOCH"
            )
            for name, value in (
                ("FAULT_DELAY_SOURCE_EPOCH", delay_epoch),
                ("FAULT_AGGTRANS_SOURCE_EPOCH", aggtrans_epoch),
                ("FAULT_BATCHMUL_SOURCE_EPOCH", batchmul_source_epoch),
            ):
                if not 1 <= value <= max_epoch:
                    raise FaultConfigurationError(
                        f"{name} must be in [1, {max_epoch}], got {value}"
                    )
            if (delay_epoch, aggtrans_epoch, batchmul_source_epoch) != (3, 4, 5):
                raise FaultConfigurationError(
                    "Figure 10 source epochs must be exactly delay=3, "
                    "AggTrans=4, and BatchMul=5"
                )
            delta_ms = _required_int(env, "FAULT_DELTA_MS")
            attack_index = _required_int(env, "FAULT_ATTACK_INDEX")
            if delta_ms != 10000:
                raise FaultConfigurationError(
                    "Figure 10 requires FAULT_DELTA_MS=10000"
                )
            if attack_index < 0:
                raise FaultConfigurationError(
                    "FAULT_ATTACK_INDEX must be non-negative"
                )
            return cls(
                mode,
                target,
                None,
                delta_ms,
                attack_index,
                selected,
                None,
                delay_epoch,
                aggtrans_epoch,
                batchmul_source_epoch,
            )

        figure10_only = [
            name
            for name in (
                "FAULT_DELAY_SOURCE_EPOCH",
                "FAULT_AGGTRANS_SOURCE_EPOCH",
                "FAULT_BATCHMUL_SOURCE_EPOCH",
            )
            if env.get(name, "").strip()
        ]
        if figure10_only:
            raise FaultConfigurationError(
                "explicit source epochs require FAULT_MODE=figure10-attack: "
                + ", ".join(figure10_only)
            )
        if mode == "delay" and target != "handoff":
            raise FaultConfigurationError(
                "FAULT_MODE=delay requires FAULT_TARGET=handoff"
            )
        if mode == "byzantine" and target not in {
            "aggtrans",
            "batchmul",
            "aggtrans+batchmul",
        }:
            raise FaultConfigurationError(
                "FAULT_MODE=byzantine requires FAULT_TARGET=aggtrans, "
                "batchmul, or aggtrans+batchmul"
            )
        if mode == "delay" and env.get("FAULT_ATTACK_INDEX", "").strip():
            raise FaultConfigurationError(
                "FAULT_ATTACK_INDEX is not valid for FAULT_MODE=delay"
            )
        if mode == "byzantine" and env.get("FAULT_DELTA_MS", "").strip():
            raise FaultConfigurationError(
                "FAULT_DELTA_MS is not valid for FAULT_MODE=byzantine"
            )
        if target != "aggtrans+batchmul" and env.get(
            "FAULT_BATCHMUL_EPOCH", ""
        ).strip():
            raise FaultConfigurationError(
                "FAULT_BATCHMUL_EPOCH requires FAULT_TARGET=aggtrans+batchmul"
            )

        epoch = _required_int(env, "FAULT_COMPUTATION_EPOCH")
        if not 1 <= epoch <= max_epoch:
            raise FaultConfigurationError(
                f"FAULT_COMPUTATION_EPOCH must be in [1, {max_epoch}], got {epoch}"
            )

        if mode == "delay":
            delta_ms = _required_int(env, "FAULT_DELTA_MS")
            if delta_ms <= 0:
                raise FaultConfigurationError("FAULT_DELTA_MS must be positive")
            attack_index = None
        else:
            delta_ms = None
            attack_index = _required_int(env, "FAULT_ATTACK_INDEX")
            if attack_index < 0:
                raise FaultConfigurationError("FAULT_ATTACK_INDEX must be non-negative")

        batchmul_epoch = None
        if target == "aggtrans+batchmul":
            batchmul_epoch = _required_int(env, "FAULT_BATCHMUL_EPOCH")
            if not 1 <= batchmul_epoch <= max_epoch:
                raise FaultConfigurationError(
                    f"FAULT_BATCHMUL_EPOCH must be in [1, {max_epoch}], "
                    f"got {batchmul_epoch}"
                )
            if batchmul_epoch != epoch + 1:
                raise FaultConfigurationError(
                    "Stage-7 Continuum Byzantine requires BatchMul at the "
                    "epoch immediately after AggTrans"
                )

        return cls(
            mode,
            target,
            epoch,
            delta_ms,
            attack_index,
            selected,
            batchmul_epoch,
        )


class ContinuumFaultController:
    """Per-process controller with structured, payload-free event logging."""

    def __init__(
        self,
        *,
        config: FaultConfig,
        n: int,
        t: int,
        layers: int,
        physical_layer_id: int,
        local_party_id: int,
    ) -> None:
        self.config = config
        self.n = n
        self.t = t
        self.layers = layers
        self.physical_layer_id = physical_layer_id
        self.local_party_id = local_party_id
        self.global_party_id = physical_layer_id * n + local_party_id
        self._delayed = False
        self._aggtrans_mutated = False
        self._batchmul_mutated = False
        self._emit(
            "config",
            attack_index=config.attack_index,
            attack_delta=(
                BYZANTINE_DELTA
                if config.aggtrans_source_epoch is not None
                or config.batchmul_source_epoch is not None
                else None
            ),
            component_epochs={
                "delay": config.delay_source_epoch,
                "aggtrans": config.aggtrans_source_epoch,
                "batchmul": config.batchmul_source_epoch,
            },
            selected_local_ids=list(config.selected_local_ids),
        )

    @classmethod
    def from_env(
        cls,
        *,
        n: int,
        t: int,
        layers: int,
        physical_layer_id: int,
        local_party_id: int,
        environ: Optional[Mapping[str, str]] = None,
    ) -> "ContinuumFaultController":
        return cls(
            config=FaultConfig.from_env(n=n, t=t, layers=layers, environ=environ),
            n=n,
            t=t,
            layers=layers,
            physical_layer_id=physical_layer_id,
            local_party_id=local_party_id,
        )

    def _emit(self, event: str, **extra: object) -> None:
        payload = {
            "schema": "continuum-fault-v1",
            "event": event,
            "protocol": "continuum",
            "mode": self.config.mode,
            "target": self.config.target,
            "computation_epoch": self.config.computation_epoch,
            "source_epochs": {
                "delay": self.config.delay_source_epoch,
                "aggtrans": self.config.aggtrans_source_epoch,
                "batchmul": self.config.batchmul_source_epoch,
            },
            "delta_ms": self.config.delta_ms,
            "attack_index": self.config.attack_index,
            "physical_layer_id": self.physical_layer_id,
            "local_party_id": self.local_party_id,
            "global_party_id": self.global_party_id,
            "wall_time": time.time(),
        }
        payload.update(extra)
        _LOG.info("%s%s", FAULT_EVENT_PREFIX, json.dumps(payload, sort_keys=True))

    def should_delay_handoff(self) -> bool:
        return (
            self.config.delay_source_epoch == self.physical_layer_id
            and self.local_party_id in self.config.selected_local_ids
        )

    async def delay_handoff_if_needed(self) -> bool:
        """Delay this dealer's AggTrans and BatchMul handoff start once."""
        if not self.should_delay_handoff():
            return False
        if self._delayed:
            raise RuntimeError("handoff delay requested twice for the same process")

        self._delayed = True
        assert self.config.delta_ms is not None
        delay_seconds = self.config.delta_ms / 1000.0
        started = time.monotonic()
        self._emit(
            "delay_scheduled",
            components=["aggtrans", "batchmul"],
        )
        await asyncio.sleep(delay_seconds)
        actual_ms = (time.monotonic() - started) * 1000.0
        self._emit(
            "delay_released",
            components=["aggtrans", "batchmul"],
            actual_delay_ms=round(actual_ms, 3),
        )
        return True

    def should_fork_aggtrans(self) -> bool:
        """Return whether this source dealer must emit a forked AggTrans view."""
        return (
            self.config.aggtrans_source_epoch == self.physical_layer_id
            and self.local_party_id in self.config.selected_local_ids
        )

    def begin_aggtrans_fork(self, batch_size: int) -> Optional[int]:
        """Validate and reserve this process's one AggTrans mutation."""
        if not self.should_fork_aggtrans():
            return None
        if self._aggtrans_mutated:
            raise RuntimeError("AggTrans Byzantine mutation requested twice")
        assert self.config.attack_index is not None
        if self.config.attack_index >= batch_size:
            raise FaultConfigurationError(
                "FAULT_ATTACK_INDEX is outside the AggTrans batch: "
                f"index={self.config.attack_index}, batch_size={batch_size}"
            )
        self._aggtrans_mutated = True
        return self.config.attack_index

    @staticmethod
    def commitment_digest(commitments: object) -> str:
        if isinstance(commitments, bytes):
            encoded = commitments
        elif isinstance(commitments, str):
            encoded = commitments.encode("utf-8")
        else:
            encoded = json.dumps(
                commitments, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:16]

    def record_aggtrans_fork(
        self,
        *,
        honest_commitments: object,
        forked_commitments: object,
    ) -> None:
        self._emit(
            "byzantine_mutation",
            component="aggtrans",
            attack_style="commitment_fork",
            attack_delta=BYZANTINE_DELTA,
            honest_commitment_digest=self.commitment_digest(honest_commitments),
            forked_commitment_digest=self.commitment_digest(forked_commitments),
            old_evaluation_proof_reused=True,
        )

    def _is_attacked_aggtrans_receiver(self, dealer_local_id: int) -> bool:
        return (
            self.config.aggtrans_source_epoch == self.physical_layer_id - 1
            and dealer_local_id in self.config.selected_local_ids
        )

    def record_aggtrans_verification(
        self,
        *,
        dealer_local_id: int,
        bacss_share_valid: bool,
        fresh_zero_valid: bool,
        old_anchor_valid: bool,
    ) -> None:
        if not self._is_attacked_aggtrans_receiver(dealer_local_id):
            return
        self._emit(
            "aggtrans_verification",
            component="aggtrans",
            dealer_local_id=dealer_local_id,
            bacss_share_valid=bool(bacss_share_valid),
            fresh_zero_valid=bool(fresh_zero_valid),
            old_anchor_valid=bool(old_anchor_valid),
            accepted=bool(
                bacss_share_valid and fresh_zero_valid and old_anchor_valid
            ),
        )

    def record_aggtrans_matching_group(
        self,
        *,
        matching_dealers: Sequence[int],
        excluded_dealers: Sequence[int],
        commitments: object,
    ) -> None:
        if not (
            self.config.aggtrans_source_epoch == self.physical_layer_id - 1
        ):
            return
        self._emit(
            "aggtrans_matching_group",
            component="aggtrans",
            commitment_digest=self.commitment_digest(commitments),
            matching_dealers=sorted(int(i) for i in matching_dealers),
            excluded_dealers=sorted(int(i) for i in excluded_dealers),
            required_matching=self.n - self.t,
        )

    def record_aggtrans_commitment_exclusion(
        self,
        *,
        dealer_local_id: int,
        commitments: object,
    ) -> None:
        if not self._is_attacked_aggtrans_receiver(dealer_local_id):
            return
        self._emit(
            "aggtrans_commitment_excluded",
            component="aggtrans",
            dealer_local_id=dealer_local_id,
            commitment_digest=self.commitment_digest(commitments),
            reason="line207_commitment_mismatch",
        )

    def record_aggtrans_common_subset(self, dealers: Sequence[int]) -> None:
        observes_byzantine = (
            self.config.aggtrans_source_epoch == self.physical_layer_id - 1
        )
        observes_delay = (
            self.config.delay_source_epoch == self.physical_layer_id - 1
        )
        if not (observes_byzantine or observes_delay):
            return
        common = sorted(int(i) for i in dealers)
        selected = sorted(set(common).intersection(self.config.selected_local_ids))
        self._emit(
            "aggtrans_common_subset",
            component="aggtrans",
            dealers=common,
            selected_dealers_in_subset=selected,
            corrupted_dealers_in_subset=selected if observes_byzantine else [],
            delayed_dealers_in_subset=selected if observes_delay else [],
        )

    def should_fork_batchmul(self) -> bool:
        """Return whether this source dealer must fork its BatchMul inputs."""
        return (
            self.config.batchmul_source_epoch == self.physical_layer_id
            and self.local_party_id in self.config.selected_local_ids
        )

    def begin_batchmul_fork(self, left_size: int, right_size: int) -> Optional[int]:
        """Validate and reserve this process's one BatchMul input mutation."""
        if not self.should_fork_batchmul():
            return None
        if self._batchmul_mutated:
            raise RuntimeError("BatchMul Byzantine mutation requested twice")
        if left_size != right_size or left_size <= 0:
            raise FaultConfigurationError(
                "BatchMul left/right batches must be non-empty and equal: "
                f"left_size={left_size}, right_size={right_size}"
            )
        assert self.config.attack_index is not None
        if self.config.attack_index >= left_size:
            raise FaultConfigurationError(
                "FAULT_ATTACK_INDEX is outside the BatchMul batch: "
                f"index={self.config.attack_index}, batch_size={left_size}"
            )
        self._batchmul_mutated = True
        return self.config.attack_index

    def record_batchmul_fork(
        self,
        *,
        honest_left_commitments: object,
        forked_left_commitments: object,
        honest_right_commitments: object,
        forked_right_commitments: object,
    ) -> None:
        self._emit(
            "byzantine_mutation",
            component="batchmul",
            attack_style="input_commitment_fork",
            attack_delta=BYZANTINE_DELTA,
            honest_left_commitment_digest=self.commitment_digest(
                honest_left_commitments
            ),
            forked_left_commitment_digest=self.commitment_digest(
                forked_left_commitments
            ),
            honest_right_commitment_digest=self.commitment_digest(
                honest_right_commitments
            ),
            forked_right_commitment_digest=self.commitment_digest(
                forked_right_commitments
            ),
            input_evaluation_proofs_reused=True,
            product_and_product_proof_recomputed=True,
        )

    def _is_attacked_batchmul_receiver(self, dealer_local_id: int) -> bool:
        return (
            self.config.batchmul_source_epoch == self.physical_layer_id - 1
            and dealer_local_id in self.config.selected_local_ids
        )

    def record_batchmul_verification(
        self,
        *,
        dealer_local_id: int,
        product_proof_valid: bool,
        bacss_share_valid: bool,
        left_anchor_valid: bool,
        right_anchor_valid: bool,
        output_zero_valid: bool,
    ) -> None:
        if not self._is_attacked_batchmul_receiver(dealer_local_id):
            return
        accepted = all(
            (
                product_proof_valid,
                bacss_share_valid,
                left_anchor_valid,
                right_anchor_valid,
                output_zero_valid,
            )
        )
        self._emit(
            "batchmul_verification",
            component="batchmul",
            dealer_local_id=dealer_local_id,
            product_proof_valid=bool(product_proof_valid),
            bacss_share_valid=bool(bacss_share_valid),
            left_anchor_valid=bool(left_anchor_valid),
            right_anchor_valid=bool(right_anchor_valid),
            output_zero_valid=bool(output_zero_valid),
            accepted=bool(accepted),
        )

    def record_batchmul_matching_group(
        self,
        *,
        matching_dealers: Sequence[int],
        excluded_dealers: Sequence[int],
        left_commitments: object,
        right_commitments: object,
    ) -> None:
        if not (
            self.config.batchmul_source_epoch == self.physical_layer_id - 1
        ):
            return
        self._emit(
            "batchmul_matching_group",
            component="batchmul",
            left_commitment_digest=self.commitment_digest(left_commitments),
            right_commitment_digest=self.commitment_digest(right_commitments),
            matching_dealers=sorted(int(i) for i in matching_dealers),
            excluded_dealers=sorted(int(i) for i in excluded_dealers),
            required_matching=self.n - self.t,
        )

    def record_batchmul_commitment_exclusion(
        self,
        *,
        dealer_local_id: int,
        left_commitments: object,
        right_commitments: object,
    ) -> None:
        if not self._is_attacked_batchmul_receiver(dealer_local_id):
            return
        self._emit(
            "batchmul_commitment_excluded",
            component="batchmul",
            dealer_local_id=dealer_local_id,
            left_commitment_digest=self.commitment_digest(left_commitments),
            right_commitment_digest=self.commitment_digest(right_commitments),
            reason="line206_input_commitment_mismatch",
        )

    def record_batchmul_common_subset(self, dealers: Sequence[int]) -> None:
        observes_byzantine = (
            self.config.batchmul_source_epoch == self.physical_layer_id - 1
        )
        observes_delay = (
            self.config.delay_source_epoch == self.physical_layer_id - 1
        )
        if not (observes_byzantine or observes_delay):
            return
        common = sorted(int(i) for i in dealers)
        selected = sorted(set(common).intersection(self.config.selected_local_ids))
        self._emit(
            "batchmul_common_subset",
            component="batchmul",
            dealers=common,
            selected_dealers_in_subset=selected,
            corrupted_dealers_in_subset=selected if observes_byzantine else [],
            delayed_dealers_in_subset=selected if observes_delay else [],
        )
