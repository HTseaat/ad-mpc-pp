from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from trusted_setup.config import (
    ConfigMismatchError,
    NodeConfig,
    ParameterError,
    SetupParams,
    load_committee_config_dir,
    write_local_configs,
)


class SetupParamsTests(unittest.TestCase):
    def test_requested_powers_round_up_once(self):
        params = SetupParams.create(16, 5, 6, run_id="round-up")
        self.assertEqual(params.requested_powers, 6)
        self.assertEqual(params.effective_powers, 8)
        self.assertEqual(params.log_q, 3)

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ParameterError):
            SetupParams.create(8, 3, 4, run_id="bad-threshold")

    def test_too_few_powers_rejected(self):
        with self.assertRaises(ParameterError):
            SetupParams.create(16, 5, 4, run_id="too-few")

    def test_non_power_of_two_n_rejected_in_current_stage(self):
        with self.assertRaises(ParameterError):
            SetupParams.create(10, 3, 4, run_id="unsupported-n")


class CommitteeConfigTests(unittest.TestCase):
    def test_complete_consistent_committee_loads(self):
        params = SetupParams.create(4, 1, 2, run_id="config-ok")
        with tempfile.TemporaryDirectory() as directory:
            write_local_configs(params, Path(directory))
            configs = load_committee_config_dir(Path(directory))
        self.assertEqual([config.node_id for config in configs], list(range(4)))
        self.assertTrue(all(config.params == params for config in configs))

    def test_parameter_mismatch_fails_closed(self):
        params = SetupParams.create(4, 1, 2, run_id="config-mismatch")
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            paths = write_local_configs(params, directory_path)
            data = json.loads(paths[1].read_text(encoding="utf-8"))
            other_params = SetupParams.create(4, 1, 2, run_id="different-run")
            other_config = NodeConfig.create(
                other_params, 1, tuple(data["peers"])
            )
            paths[1].write_text(
                json.dumps(other_config.as_dict()), encoding="utf-8"
            )
            with self.assertRaises(ConfigMismatchError):
                load_committee_config_dir(directory_path)


if __name__ == "__main__":
    unittest.main()
