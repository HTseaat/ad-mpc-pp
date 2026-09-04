"""Fail-closed configuration for the Figure 10 crash-stop experiment.

The dynamic Continuum committees lose the same ``count`` local party IDs in
every computation epoch.  The static Dumbo-MPC committee loses a fresh block
of ``count`` IDs per epoch and a stopped process never rejoins.  Figure 10 uses
``count=t``; the environment variable remains available for smaller smoke
tests.
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
    """Raised before protocol work when the experiment settings are unsafe."""


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
    def dynamic_silent_local_ids(self) -> Tuple[int, ...]:
        if not self.enabled:
            return ()
        return tuple(range(self.n - self.count, self.n))

    def static_new_silent_local_ids(self, epoch: int) -> Tuple[int, ...]:
        """Return the fresh static-committee failures introduced at ``epoch``."""
        if not self.enabled or epoch < self.start_epoch:
            return ()
        group = epoch - self.start_epoch
        stop = self.n - group * self.count
        start = max(0, stop - self.count)
        if stop <= 0:
            return ()
        return tuple(range(start, stop))

    def static_first_silent_epoch(self, local_party_id: int) -> Optional[int]:
        if not self.enabled:
            return None
        distance_from_end = self.n - 1 - local_party_id
        return self.start_epoch + distance_from_end // self.count

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
            return cls(mode="none", count=0, start_epoch=1, n=n, t=t, layers=layers)

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
        max_epoch = layers - 2
        if not 1 <= start_epoch <= max_epoch:
            raise FaultAccumulationConfigurationError(
                "FAULT_ACCUMULATION_START_EPOCH must be in "
                f"[1, {max_epoch}], got {start_epoch}"
            )
        return cls(
            mode=mode,
            count=count,
            start_epoch=start_epoch,
            n=n,
            t=t,
            layers=layers,
        )


class FaultAccumulationController:
    """Per-process schedule helper with machine-readable event logging."""

    def __init__(
        self,
        *,
        config: FaultAccumulationConfig,
        protocol: str,
        local_party_id: int,
        physical_layer_id: Optional[int] = None,
    ) -> None:
        if protocol not in {"continuum", "dumbo-mpc"}:
            raise FaultAccumulationConfigurationError(
                f"unsupported accumulation protocol: {protocol!r}"
            )
        if not 0 <= local_party_id < config.n:
            raise FaultAccumulationConfigurationError("local party ID is out of range")
        if protocol == "continuum" and physical_layer_id is None:
            raise FaultAccumulationConfigurationError(
                "Continuum accumulation requires a physical layer ID"
            )
        self.config = config
        self.protocol = protocol
        self.local_party_id = local_party_id
        self.physical_layer_id = physical_layer_id
        self._silent_logged = False
        if config.enabled:
            self._emit(
                "config",
                selected_local_ids=list(config.dynamic_silent_local_ids)
                if protocol == "continuum"
                else None,
                first_silent_epoch=(
                    config.static_first_silent_epoch(local_party_id)
                    if protocol == "dumbo-mpc"
                    else None
                ),
            )

    @classmethod
    def from_env(
        cls,
        *,
        protocol: str,
        n: int,
        t: int,
        layers: int,
        local_party_id: int,
        physical_layer_id: Optional[int] = None,
        environ: Optional[Mapping[str, str]] = None,
    ) -> "FaultAccumulationController":
        return cls(
            config=FaultAccumulationConfig.from_env(
                n=n, t=t, layers=layers, environ=environ
            ),
            protocol=protocol,
            local_party_id=local_party_id,
            physical_layer_id=physical_layer_id,
        )

    def _emit(self, event: str, **extra: object) -> None:
        payload = {
            "schema": "figure10-fault-accumulation-v1",
            "event": event,
            "protocol": self.protocol,
            "mode": self.config.mode,
            "n": self.config.n,
            "t": self.config.t,
            "layers": self.config.layers,
            "count": self.config.count,
            "start_epoch": self.config.start_epoch,
            "local_party_id": self.local_party_id,
            "physical_layer_id": self.physical_layer_id,
            "global_party_id": (
                self.physical_layer_id * self.config.n + self.local_party_id
                if self.physical_layer_id is not None
                else self.local_party_id
            ),
        }
        payload.update(extra)
        _LOG.warning(FAULT_ACCUM_EVENT_PREFIX + json.dumps(payload, sort_keys=True))

    def continuum_should_be_silent(self) -> bool:
        """Whether this process is one of the failed computation members."""
        layer = self.physical_layer_id
        if (
            not self.config.enabled
            or self.protocol != "continuum"
            or layer is None
            or not 1 <= layer <= self.config.layers - 2
        ):
            return False
        return self.local_party_id in self.config.dynamic_silent_local_ids

    def dumbo_should_stop_before_layer(self, layer_idx: int) -> bool:
        """Whether the static process first becomes silent before this layer."""
        if not self.config.enabled or self.protocol != "dumbo-mpc":
            return False
        epoch = layer_idx + 1
        return self.config.static_first_silent_epoch(self.local_party_id) == epoch

    def log_silent_entered(self, *, epoch: int) -> None:
        if self._silent_logged:
            return
        self._silent_logged = True
        if self.protocol == "dumbo-mpc":
            new_silent_ids = list(self.config.static_new_silent_local_ids(epoch))
            cumulative_silent = min(
                self.config.n,
                (epoch - self.config.start_epoch + 1) * self.config.count,
            )
        else:
            new_silent_ids = list(self.config.dynamic_silent_local_ids)
            cumulative_silent = self.config.count
        self._emit(
            "silent_entered",
            epoch=epoch,
            permanent=True,
            new_silent_local_ids=new_silent_ids,
            active_committee_silent_count=cumulative_silent,
        )
