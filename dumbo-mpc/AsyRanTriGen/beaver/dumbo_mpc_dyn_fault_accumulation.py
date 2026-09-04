"""Dumbo-MPC Figure 10 variant with permanent cumulative crash-stop faults."""

import json
import logging
import time

from beaver.dumbo_mpc_dyn import BEAVER as FullBEAVER
from beaver.fault_accumulation import (
    FaultAccumulationConfigurationError,
    FaultAccumulationController,
)


class BEAVER(FullBEAVER):
    """Silence a fresh configured block before every circuit epoch."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fault_accumulation = FaultAccumulationController.from_env(
            protocol="dumbo-mpc",
            n=self.n,
            t=self.t,
            # The shared schedule records physical layers; Dumbo receives only
            # the computation depth and therefore adds logical input/output.
            layers=self.layers + 2,
            local_party_id=self.my_id,
        )
        if not self.fault_accumulation.config.enabled:
            raise FaultAccumulationConfigurationError(
                "dumbo mode fault-accumulation requires "
                "FAULT_ACCUMULATION_MODE=silent"
            )
        self._fault_run_started_at = None

    async def run_beaver(self, node_communicator):
        self._fault_run_started_at = time.monotonic()
        return await super().run_beaver(node_communicator)

    def _should_stop_before_layer(self, layer_idx):
        should_stop = self.fault_accumulation.dumbo_should_stop_before_layer(layer_idx)
        if should_stop:
            self.fault_accumulation.log_silent_entered(epoch=layer_idx + 1)
        return should_stop

    def _on_layer_completed(self, layer_idx):
        elapsed = time.monotonic() - self._fault_run_started_at
        payload = {
            "schema": "figure10-progress-v1",
            "protocol": "dumbo-mpc",
            "event": "epoch_completed",
            "epoch": layer_idx + 1,
            "local_party_id": self.my_id,
            "elapsed_seconds": elapsed,
        }
        logging.getLogger("figure10_progress").warning(
            "FIGURE10_PROGRESS_EVENT " + json.dumps(payload, sort_keys=True)
        )
