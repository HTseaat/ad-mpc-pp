"""Opt-in fault configuration for AD-MPC adversarial experiments.

The default configuration is a strict no-op. Supported behaviors are a fixed
ADtrans contribution delay and an internally consistent ADtrans outgoing-share
fork. The formal Figure 10 profile composes them at source epochs 3/4 with a
10,000 ms delay. Other protocol components and the transport layer are left
untouched.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import os
import time
from typing import Mapping, Optional, Sequence, Tuple


FAULT_EVENT_PREFIX = "FAULT_EVENT "
BYZANTINE_DELTA = 1
_LOG = logging.getLogger("fault_injection")


class FaultConfigurationError(ValueError):
    """Raised before MPC computation when fault settings are ambiguous."""


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
    figure10_delay_epoch: Optional[int] = None
    figure10_adtrans_epoch: Optional[int] = None

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
    def adtrans_source_epoch(self) -> Optional[int]:
        if self.mode == "byzantine":
            return self.computation_epoch
        if self.mode == "figure10-attack":
            return self.figure10_adtrans_epoch
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
            "FAULT_DELAY_SOURCE_EPOCH",
            "FAULT_ADTRANS_SOURCE_EPOCH",
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
        if target != "adtrans":
            raise FaultConfigurationError(
                "AD-MPC fault modes require FAULT_TARGET=adtrans"
            )

        max_epoch = layers - 2
        if mode == "figure10-attack":
            if env.get("FAULT_COMPUTATION_EPOCH", "").strip():
                raise FaultConfigurationError(
                    "Figure 10 uses explicit source epochs, not "
                    "FAULT_COMPUTATION_EPOCH"
                )
            delay_epoch = _required_int(env, "FAULT_DELAY_SOURCE_EPOCH")
            adtrans_epoch = _required_int(env, "FAULT_ADTRANS_SOURCE_EPOCH")
            for name, value in (
                ("FAULT_DELAY_SOURCE_EPOCH", delay_epoch),
                ("FAULT_ADTRANS_SOURCE_EPOCH", adtrans_epoch),
            ):
                if not 1 <= value <= max_epoch:
                    raise FaultConfigurationError(
                        f"{name} must be in [1, {max_epoch}], got {value}"
                    )
            if (delay_epoch, adtrans_epoch) != (3, 4):
                raise FaultConfigurationError(
                    "Figure 10 source epochs must be exactly delay=3 and ADtrans=4"
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
                delay_epoch,
                adtrans_epoch,
            )

        figure10_only = [
            name
            for name in ("FAULT_DELAY_SOURCE_EPOCH", "FAULT_ADTRANS_SOURCE_EPOCH")
            if env.get(name, "").strip()
        ]
        if figure10_only:
            raise FaultConfigurationError(
                "explicit source epochs require FAULT_MODE=figure10-attack: "
                + ", ".join(figure10_only)
            )

        epoch = _required_int(env, "FAULT_COMPUTATION_EPOCH")
        if not 1 <= epoch <= max_epoch:
            raise FaultConfigurationError(
                f"FAULT_COMPUTATION_EPOCH must be in [1, {max_epoch}], got {epoch}"
            )

        if mode == "delay":
            if env.get("FAULT_ATTACK_INDEX", "").strip():
                raise FaultConfigurationError(
                    "FAULT_ATTACK_INDEX is not valid for FAULT_MODE=delay"
                )
            delta_ms = _required_int(env, "FAULT_DELTA_MS")
            if delta_ms <= 0:
                raise FaultConfigurationError("FAULT_DELTA_MS must be positive")
            return cls("delay", target, epoch, delta_ms, None, selected)

        if env.get("FAULT_DELTA_MS", "").strip():
            raise FaultConfigurationError(
                "FAULT_DELTA_MS is not valid for FAULT_MODE=byzantine"
            )
        attack_index = _required_int(env, "FAULT_ATTACK_INDEX")
        if attack_index < 0:
            raise FaultConfigurationError("FAULT_ATTACK_INDEX must be non-negative")
        return cls("byzantine", target, epoch, None, attack_index, selected)


class ADMPCFaultController:
    """Per-process AD-MPC controller with structured, payload-free events."""

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
        self._adtrans_mutated = False
        self._emit(
            "config",
            attack_index=config.attack_index,
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
    ) -> "ADMPCFaultController":
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
            "schema": "admpc-fault-v1",
            "event": event,
            "protocol": "admpc",
            "mode": self.config.mode,
            "target": self.config.target,
            "computation_epoch": self.config.computation_epoch,
            "source_epochs": {
                "delay": self.config.delay_source_epoch,
                "adtrans": self.config.adtrans_source_epoch,
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

    def should_delay_adtrans(self) -> bool:
        return (
            self.config.delay_source_epoch == self.physical_layer_id
            and self.local_party_id in self.config.selected_local_ids
        )

    def observes_delay_destination(self) -> bool:
        return (
            self.config.delay_source_epoch == self.physical_layer_id - 1
        )

    def observes_attack_destination(self) -> bool:
        return self.config.adtrans_source_epoch == self.physical_layer_id - 1

    def observes_target_destination(self) -> bool:
        return self.observes_delay_destination() or self.observes_attack_destination()

    def record_adtrans_acss_complete(self, dealer_local_ids: object) -> None:
        if self.observes_target_destination():
            self._emit(
                "adtrans_acss_complete",
                dealer_local_ids=sorted(int(i) for i in dealer_local_ids),
            )

    def record_adtrans_common_subset(self, dealer_local_ids: object) -> None:
        if self.observes_target_destination():
            dealers = sorted(int(i) for i in dealer_local_ids)
            corrupted = sorted(set(dealers).intersection(self.config.selected_local_ids))
            self._emit(
                "adtrans_common_subset",
                dealer_local_ids=dealers,
                corrupted_dealers_in_subset=corrupted,
            )

    def should_mutate_adtrans(self) -> bool:
        return (
            self.config.adtrans_source_epoch == self.physical_layer_id
            and self.local_party_id in self.config.selected_local_ids
        )

    def begin_adtrans_mutation(self, batch_size: int) -> Optional[int]:
        if not self.should_mutate_adtrans():
            return None
        if self._adtrans_mutated:
            raise RuntimeError("ADtrans Byzantine mutation requested twice")
        if batch_size <= 0:
            raise FaultConfigurationError("ADtrans outgoing batch must be non-empty")
        assert self.config.attack_index is not None
        if self.config.attack_index >= batch_size:
            raise FaultConfigurationError(
                "FAULT_ATTACK_INDEX is outside the ADtrans batch: "
                f"index={self.config.attack_index}, batch_size={batch_size}"
            )
        self._adtrans_mutated = True
        return self.config.attack_index

    def record_adtrans_mutation(self, *, batch_size: int) -> None:
        self._emit(
            "byzantine_mutation",
            component="adtrans",
            attack_style="outgoing_share_fork",
            attack_delta=BYZANTINE_DELTA,
            batch_size=int(batch_size),
            outgoing_copy=True,
            acss_resharing_recomputed=True,
            commitment_recomputed=True,
            mask_recomputed=True,
            consistency_proof_recomputed=True,
        )

    def requires_adtrans_verification(self, dealer_local_id: int) -> bool:
        """Force the paper's line-204 checks for the selected experiment dealer.

        The legacy implementation skips proposal verification for dealer IDs
        above ``2t``. The selected last-t dealer falls in that range, so the
        formal experiment must opt back into the existing checks.
        """
        return (
            self.observes_attack_destination()
            and dealer_local_id in self.config.selected_local_ids
        )

    def record_adtrans_verification(
        self,
        *,
        dealer_local_id: int,
        share_binding_valid: bool,
        consistency_proof_valid: Optional[bool],
    ) -> None:
        if not self.requires_adtrans_verification(dealer_local_id):
            return
        accepted = bool(share_binding_valid and consistency_proof_valid)
        self._emit(
            "adtrans_verification",
            component="adtrans",
            dealer_local_id=int(dealer_local_id),
            legacy_fast_path_overridden=True,
            share_binding_valid=bool(share_binding_valid),
            consistency_proof_valid=(
                None
                if consistency_proof_valid is None
                else bool(consistency_proof_valid)
            ),
            accepted=accepted,
        )

    def record_adtrans_robust_filter(
        self,
        *,
        candidate_dealers: Sequence[int],
        decoder_error_dealers: Sequence[int],
        post_decode_mismatch_dealers: Sequence[int],
        filtered_dealers: Sequence[int],
        matching_randomness_dealers: Sequence[int],
    ) -> None:
        if not (
            self.observes_attack_destination()
        ):
            return
        all_errors = sorted(
            set(int(i) for i in decoder_error_dealers).union(
                int(i) for i in post_decode_mismatch_dealers
            )
        )
        corrupted = sorted(
            set(all_errors).intersection(
                self.config.selected_local_ids
            )
        )
        self._emit(
            "adtrans_robust_filter",
            component="adtrans",
            candidate_dealers=sorted(int(i) for i in candidate_dealers),
            decoder_error_dealers=sorted(
                int(i) for i in decoder_error_dealers
            ),
            post_decode_mismatch_dealers=sorted(
                int(i) for i in post_decode_mismatch_dealers
            ),
            all_candidates_checked=True,
            error_dealers=all_errors,
            filtered_dealers=sorted(int(i) for i in filtered_dealers),
            matching_randomness_dealers=sorted(
                int(i) for i in matching_randomness_dealers
            ),
            corrupted_dealers_detected=corrupted,
            reason="line207_robust_reconstruction_error",
        )

    async def delay_adtrans_if_needed(self) -> bool:
        """Delay this dealer's ADtrans contribution start exactly once."""
        if not self.should_delay_adtrans():
            return False
        if self._delayed:
            raise RuntimeError("ADtrans delay requested twice for the same process")

        self._delayed = True
        assert self.config.delta_ms is not None
        delay_seconds = self.config.delta_ms / 1000.0
        started = time.monotonic()
        self._emit("delay_scheduled", components=["adtrans"])
        await asyncio.sleep(delay_seconds)
        actual_ms = (time.monotonic() - started) * 1000.0
        self._emit(
            "delay_released",
            components=["adtrans"],
            actual_delay_ms=round(actual_ms, 3),
        )
        return True
