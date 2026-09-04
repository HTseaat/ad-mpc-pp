import asyncio
import json
import unittest

from beaver.adversarial_faults import (
    ContinuumFaultController,
    FaultConfig,
    FaultConfigurationError,
)


class FaultConfigTests(unittest.TestCase):
    def test_default_is_noop_and_uses_last_t_ids(self):
        config = FaultConfig.from_env(n=16, t=5, layers=8, environ={})
        self.assertEqual(config.mode, "none")
        self.assertFalse(config.enabled)
        self.assertEqual(config.selected_local_ids, (11, 12, 13, 14, 15))

    def test_fixed_delay_configuration(self):
        config = FaultConfig.from_env(
            n=4,
            t=1,
            layers=3,
            environ={
                "FAULT_MODE": "delay",
                "FAULT_TARGET": "handoff",
                "FAULT_COMPUTATION_EPOCH": "1",
                "FAULT_DELTA_MS": "25",
            },
        )
        self.assertEqual(config.delta_ms, 25)
        self.assertEqual(config.selected_local_ids, (3,))

    def test_none_rejects_stale_parameters(self):
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(
                n=4,
                t=1,
                layers=3,
                environ={"FAULT_MODE": "none", "FAULT_DELTA_MS": "10"},
            )

    def test_invalid_epoch_and_delta_fail_closed(self):
        base = {
            "FAULT_MODE": "delay",
            "FAULT_TARGET": "handoff",
            "FAULT_COMPUTATION_EPOCH": "2",
            "FAULT_DELTA_MS": "10",
        }
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=3, environ=base)

        base["FAULT_COMPUTATION_EPOCH"] = "1"
        base["FAULT_DELTA_MS"] = "0"
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=3, environ=base)

    def test_aggtrans_byzantine_configuration_uses_last_t_ids(self):
        config = FaultConfig.from_env(
            n=16,
            t=5,
            layers=8,
            environ={
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "aggtrans",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_ATTACK_INDEX": "7",
            },
        )
        self.assertEqual(config.attack_index, 7)
        self.assertIsNone(config.delta_ms)
        self.assertEqual(config.selected_local_ids, (11, 12, 13, 14, 15))

    def test_batchmul_byzantine_configuration_uses_last_t_ids(self):
        config = FaultConfig.from_env(
            n=16,
            t=5,
            layers=8,
            environ={
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "batchmul",
                "FAULT_COMPUTATION_EPOCH": "4",
                "FAULT_ATTACK_INDEX": "7",
            },
        )
        self.assertEqual(config.target, "batchmul")
        self.assertEqual(config.attack_index, 7)
        self.assertEqual(config.selected_local_ids, (11, 12, 13, 14, 15))

    def test_combined_byzantine_configuration_has_two_adjacent_epochs(self):
        env = {
            "FAULT_MODE": "byzantine",
            "FAULT_TARGET": "aggtrans+batchmul",
            "FAULT_COMPUTATION_EPOCH": "3",
            "FAULT_BATCHMUL_EPOCH": "4",
            "FAULT_ATTACK_INDEX": "0",
        }
        config = FaultConfig.from_env(n=4, t=1, layers=8, environ=env)
        self.assertEqual(config.computation_epoch, 3)
        self.assertEqual(config.batchmul_epoch, 4)

        agg_source = ContinuumFaultController.from_env(
            n=4, t=1, layers=8, physical_layer_id=3, local_party_id=3,
            environ=env,
        )
        batch_source = ContinuumFaultController.from_env(
            n=4, t=1, layers=8, physical_layer_id=4, local_party_id=3,
            environ=env,
        )
        self.assertTrue(agg_source.should_fork_aggtrans())
        self.assertFalse(agg_source.should_fork_batchmul())
        self.assertFalse(batch_source.should_fork_aggtrans())
        self.assertTrue(batch_source.should_fork_batchmul())

    def test_combined_byzantine_epochs_fail_closed(self):
        base = {
            "FAULT_MODE": "byzantine",
            "FAULT_TARGET": "aggtrans+batchmul",
            "FAULT_COMPUTATION_EPOCH": "3",
            "FAULT_BATCHMUL_EPOCH": "5",
            "FAULT_ATTACK_INDEX": "0",
        }
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=8, environ=base)

        missing = dict(base)
        missing.pop("FAULT_BATCHMUL_EPOCH")
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=8, environ=missing)

    def test_figure10_attack_uses_source_epochs_three_four_five(self):
        env = {
            "FAULT_MODE": "figure10-attack",
            "FAULT_TARGET": "handoff+aggtrans+batchmul",
            "FAULT_DELAY_SOURCE_EPOCH": "3",
            "FAULT_AGGTRANS_SOURCE_EPOCH": "4",
            "FAULT_BATCHMUL_SOURCE_EPOCH": "5",
            "FAULT_DELTA_MS": "10000",
            "FAULT_ATTACK_INDEX": "0",
        }
        config = FaultConfig.from_env(n=16, t=5, layers=8, environ=env)
        self.assertEqual(config.delay_source_epoch, 3)
        self.assertEqual(config.aggtrans_source_epoch, 4)
        self.assertEqual(config.batchmul_source_epoch, 5)

        delay_source = ContinuumFaultController.from_env(
            n=16, t=5, layers=8, physical_layer_id=3, local_party_id=11,
            environ=env,
        )
        aggtrans_source = ContinuumFaultController.from_env(
            n=16, t=5, layers=8, physical_layer_id=4, local_party_id=11,
            environ=env,
        )
        batchmul_source = ContinuumFaultController.from_env(
            n=16, t=5, layers=8, physical_layer_id=5, local_party_id=11,
            environ=env,
        )
        self.assertTrue(delay_source.should_delay_handoff())
        self.assertFalse(delay_source.should_fork_aggtrans())
        self.assertTrue(aggtrans_source.should_fork_aggtrans())
        self.assertFalse(aggtrans_source.should_fork_batchmul())
        self.assertTrue(batchmul_source.should_fork_batchmul())

    def test_figure10_attack_rejects_wrong_schedule_delay_or_legacy_epochs(self):
        base = {
            "FAULT_MODE": "figure10-attack",
            "FAULT_TARGET": "handoff+aggtrans+batchmul",
            "FAULT_DELAY_SOURCE_EPOCH": "3",
            "FAULT_AGGTRANS_SOURCE_EPOCH": "4",
            "FAULT_BATCHMUL_SOURCE_EPOCH": "6",
            "FAULT_DELTA_MS": "10000",
            "FAULT_ATTACK_INDEX": "0",
        }
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=16, t=5, layers=8, environ=base)
        wrong_consecutive = dict(
            base,
            FAULT_DELAY_SOURCE_EPOCH="2",
            FAULT_AGGTRANS_SOURCE_EPOCH="3",
            FAULT_BATCHMUL_SOURCE_EPOCH="4",
        )
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(
                n=16, t=5, layers=8, environ=wrong_consecutive
            )
        wrong_delay = dict(base, FAULT_BATCHMUL_SOURCE_EPOCH="5", FAULT_DELTA_MS="9999")
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=16, t=5, layers=8, environ=wrong_delay)
        legacy = dict(base)
        legacy["FAULT_BATCHMUL_SOURCE_EPOCH"] = "5"
        legacy["FAULT_COMPUTATION_EPOCH"] = "3"
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=16, t=5, layers=8, environ=legacy)

    def test_byzantine_invalid_combinations_fail_closed(self):
        base = {
            "FAULT_MODE": "byzantine",
            "FAULT_TARGET": "aggtrans",
            "FAULT_COMPUTATION_EPOCH": "1",
            "FAULT_ATTACK_INDEX": "0",
        }
        invalid = dict(base, FAULT_TARGET="handoff")
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=3, environ=invalid)

        invalid = dict(base, FAULT_DELTA_MS="10")
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=3, environ=invalid)

        invalid = dict(base, FAULT_ATTACK_INDEX="-1")
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=3, environ=invalid)

    def test_only_selected_source_epoch_delays(self):
        env = {
            "FAULT_MODE": "delay",
            "FAULT_TARGET": "handoff",
            "FAULT_COMPUTATION_EPOCH": "1",
            "FAULT_DELTA_MS": "1",
        }
        selected = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=3,
            physical_layer_id=1,
            local_party_id=3,
            environ=env,
        )
        other_party = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=3,
            physical_layer_id=1,
            local_party_id=2,
            environ=env,
        )
        input_layer = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=3,
            physical_layer_id=0,
            local_party_id=3,
            environ=env,
        )
        self.assertTrue(selected.should_delay_handoff())
        self.assertFalse(other_party.should_delay_handoff())
        self.assertFalse(input_layer.should_delay_handoff())
        self.assertTrue(asyncio.run(selected.delay_handoff_if_needed()))

    def test_delay_destination_records_selected_dealers_in_common_subsets(self):
        destination = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=4,
            local_party_id=0,
            environ={
                "FAULT_MODE": "delay",
                "FAULT_TARGET": "handoff",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_DELTA_MS": "2000",
            },
        )
        with self.assertLogs("fault_injection", level="INFO") as captured:
            destination.record_aggtrans_common_subset([0, 1, 2])
            destination.record_batchmul_common_subset([0, 1, 2, 3])

        events = [
            json.loads(line.split("FAULT_EVENT ", 1)[1])
            for line in captured.output
        ]
        self.assertEqual(events[0]["delayed_dealers_in_subset"], [])
        self.assertEqual(events[1]["delayed_dealers_in_subset"], [3])
        self.assertEqual(events[0]["corrupted_dealers_in_subset"], [])
        self.assertEqual(events[1]["corrupted_dealers_in_subset"], [])

    def test_only_last_t_source_dealers_fork_aggtrans(self):
        env = {
            "FAULT_MODE": "byzantine",
            "FAULT_TARGET": "aggtrans",
            "FAULT_COMPUTATION_EPOCH": "3",
            "FAULT_ATTACK_INDEX": "4",
        }
        selected = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=3,
            local_party_id=3,
            environ=env,
        )
        honest = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=3,
            local_party_id=2,
            environ=env,
        )
        destination = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=4,
            local_party_id=3,
            environ=env,
        )
        self.assertTrue(selected.should_fork_aggtrans())
        self.assertEqual(selected.begin_aggtrans_fork(5), 4)
        self.assertFalse(honest.should_fork_aggtrans())
        self.assertFalse(destination.should_fork_aggtrans())
        with self.assertRaises(RuntimeError):
            selected.begin_aggtrans_fork(5)

    def test_attack_index_is_checked_against_runtime_batch(self):
        controller = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=3,
            local_party_id=3,
            environ={
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "aggtrans",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_ATTACK_INDEX": "5",
            },
        )
        with self.assertRaises(FaultConfigurationError):
            controller.begin_aggtrans_fork(5)

    def test_only_last_t_source_dealers_fork_batchmul(self):
        env = {
            "FAULT_MODE": "byzantine",
            "FAULT_TARGET": "batchmul",
            "FAULT_COMPUTATION_EPOCH": "4",
            "FAULT_ATTACK_INDEX": "4",
        }
        selected = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=4,
            local_party_id=3,
            environ=env,
        )
        honest = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=4,
            local_party_id=2,
            environ=env,
        )
        destination = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=5,
            local_party_id=3,
            environ=env,
        )
        self.assertTrue(selected.should_fork_batchmul())
        self.assertEqual(selected.begin_batchmul_fork(5, 5), 4)
        self.assertFalse(honest.should_fork_batchmul())
        self.assertFalse(destination.should_fork_batchmul())
        with self.assertRaises(RuntimeError):
            selected.begin_batchmul_fork(5, 5)

    def test_batchmul_runtime_batch_validation_fails_closed(self):
        controller = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=4,
            local_party_id=3,
            environ={
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "batchmul",
                "FAULT_COMPUTATION_EPOCH": "4",
                "FAULT_ATTACK_INDEX": "5",
            },
        )
        with self.assertRaises(FaultConfigurationError):
            controller.begin_batchmul_fork(5, 5)

        unequal = ContinuumFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=4,
            local_party_id=3,
            environ={
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "batchmul",
                "FAULT_COMPUTATION_EPOCH": "4",
                "FAULT_ATTACK_INDEX": "0",
            },
        )
        with self.assertRaises(FaultConfigurationError):
            unequal.begin_batchmul_fork(4, 5)


if __name__ == "__main__":
    unittest.main()
