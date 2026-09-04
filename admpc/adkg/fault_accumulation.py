"""Opt-in permanent-silence schedule for the Figure 10 AD-MPC run.

Every computation committee loses the last ``count`` local parties.  The
committees are distinct physical layers, so the selected global processes are
fresh in every epoch.  Input and output committees are never silenced.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from typing import Mapping, Optional, Tuple


FAULT_ACCUM_EVENT_PREFIX = "FAULT_ACCUM_EVENT "
_LOG = logging.getLogger("fault_accumulation")


class FaultAccumulationConfigurationError(ValueError):
    """Raised before protocol work when the schedule is ambiguous."""


def _optional_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise FaultAccumulationConfigurationError(
            f"{name} must be an integer, got {raw!r}"
        ) from exc


@dataclass(frozen=True)
class FaultAccumulationConfig:
    mode: str
    count: int
    start_epoch: int
    n: int
    t: int
    layers: int

    @property
    def enabled(self) -> bool:
        return self.mode == "silent"

    @property
    def silent_local_ids(self) -> Tuple[int, ...]:
        if not self.enabled:
            return ()
        return tuple(range(self.n - self.count, self.n))

    @classmethod
    def from_env(
        cls,
        *,
        n: int,
        t: int,
        layers: int,
        environ: Optional[Mapping[str, str]] = None,
    ) -> "FaultAccumulationConfig":
        env = os.environ if environ is None else environ
        mode = env.get("FAULT_ACCUMULATION_MODE", "none").strip().lower() or "none"
        controlled = ("FAULT_ACCUMULATION_COUNT", "FAULT_ACCUMULATION_START_EPOCH")

        if n < 3 * t + 1:
            raise FaultAccumulationConfigurationError("n must satisfy n >= 3*t+1")
        if layers < 3:
            raise FaultAccumulationConfigurationError(
                "layers must include input, computation, and output"
            )
        if mode not in {"none", "silent"}:
            raise FaultAccumulationConfigurationError(
                f"unsupported FAULT_ACCUMULATION_MODE={mode!r}; expected none or silent"
            )
        if mode == "none":
            stale = [name for name in controlled if env.get(name, "").strip()]
            if stale:
                raise FaultAccumulationConfigurationError(
                    "accumulation parameters require FAULT_ACCUMULATION_MODE=silent: "
                    + ", ".join(stale)
                )
            return cls("none", 0, 1, n, t, layers)

        existing_fault_mode = env.get("FAULT_MODE", "none").strip().lower() or "none"
        if existing_fault_mode != "none":
            raise FaultAccumulationConfigurationError(
                "FAULT_ACCUMULATION_MODE=silent cannot be combined with FAULT_MODE"
            )

        count = _optional_int(env, "FAULT_ACCUMULATION_COUNT", t)
        start_epoch = _optional_int(env, "FAULT_ACCUMULATION_START_EPOCH", 1)
        if not 1 <= count <= t:
            raise FaultAccumulationConfigurationError(
                f"FAULT_ACCUMULATION_COUNT must be in [1, t={t}], got {count}"
            )
        if not 1 <= start_epoch <= layers - 2:
            raise FaultAccumulationConfigurationError(
                "FAULT_ACCUMULATION_START_EPOCH must be in "
                f"[1, {layers - 2}], got {start_epoch}"
            )
        return cls("silent", count, start_epoch, n, t, layers)


class ADMPCFaultAccumulationController:
    """Per-process AD-MPC silence decision and structured event logging."""

    def __init__(
        self,
        *,
        config: FaultAccumulationConfig,
        physical_layer_id: int,
        local_party_id: int,
    ) -> None:
        if not 0 <= physical_layer_id < config.layers:
            raise FaultAccumulationConfigurationError("physical layer ID is out of range")
        if not 0 <= local_party_id < config.n:
            raise FaultAccumulationConfigurationError("local party ID is out of range")
        self.config = config
        self.physical_layer_id = physical_layer_id
        self.local_party_id = local_party_id
        self._silent_logged = False
        if config.enabled:
            self._emit("config", selected_local_ids=list(config.silent_local_ids))

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
    ) -> "ADMPCFaultAccumulationController":
        return cls(
            config=FaultAccumulationConfig.from_env(
                n=n, t=t, layers=layers, environ=environ
            ),
            physical_layer_id=physical_layer_id,
            local_party_id=local_party_id,
        )

    def _emit(self, event: str, **extra: object) -> None:
        payload = {
            "schema": "figure10-fault-accumulation-v1",
            "event": event,
            "protocol": "admpc",
            "mode": self.config.mode,
            "n": self.config.n,
            "t": self.config.t,
            "layers": self.config.layers,
            "count": self.config.count,
            "start_epoch": self.config.start_epoch,
            "physical_layer_id": self.physical_layer_id,
            "local_party_id": self.local_party_id,
            "global_party_id": (
                self.physical_layer_id * self.config.n + self.local_party_id
            ),
        }
        payload.update(extra)
        _LOG.warning(FAULT_ACCUM_EVENT_PREFIX + json.dumps(payload, sort_keys=True))

    def should_be_silent(self) -> bool:
        return (
            self.config.enabled
            and self.config.start_epoch
            <= self.physical_layer_id
            <= self.config.layers - 2
            and self.local_party_id in self.config.silent_local_ids
        )

    def log_silent_entered(self) -> None:
        if self._silent_logged:
            return
        self._silent_logged = True
        self._emit(
            "silent_entered",
            epoch=self.physical_layer_id,
            permanent=True,
            new_silent_local_ids=list(self.config.silent_local_ids),
            active_committee_silent_count=self.config.count,
        )
