import asyncio
import unittest

from adkg.adversarial_faults import (
    ADMPCFaultController,
    BYZANTINE_DELTA,
    FaultConfig,
    FaultConfigurationError,
)
from adkg.adtrans_byzantine import build_adtrans_outgoing_copy
from adkg.robust_reconstruction import find_inconsistent_dealers


class FaultConfigTests(unittest.TestCase):
    def test_default_is_noop_and_uses_last_t_ids(self):
        config = FaultConfig.from_env(n=16, t=5, layers=8, environ={})
        self.assertEqual(config.mode, "none")
        self.assertFalse(config.enabled)
        self.assertEqual(config.selected_local_ids, (11, 12, 13, 14, 15))

    def test_fixed_d6_delay_configuration(self):
        config = FaultConfig.from_env(
            n=4,
            t=1,
            layers=8,
            environ={
                "FAULT_MODE": "delay",
                "FAULT_TARGET": "adtrans",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_DELTA_MS": "2000",
            },
        )
        self.assertEqual(config.computation_epoch, 3)
        self.assertEqual(config.delta_ms, 2000)
        self.assertEqual(config.selected_local_ids, (3,))

    def test_none_rejects_stale_parameters(self):
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(
                n=4,
                t=1,
                layers=8,
                environ={"FAULT_MODE": "none", "FAULT_DELTA_MS": "10"},
            )

    def test_wrong_target_and_attack_index_fail_closed(self):
        base = {
            "FAULT_MODE": "delay",
            "FAULT_TARGET": "handoff",
            "FAULT_COMPUTATION_EPOCH": "3",
            "FAULT_DELTA_MS": "10",
        }
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=8, environ=base)

        base["FAULT_TARGET"] = "adtrans"
        base["FAULT_ATTACK_INDEX"] = "0"
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=8, environ=base)

    def test_invalid_epoch_and_delta_fail_closed(self):
        base = {
            "FAULT_MODE": "delay",
            "FAULT_TARGET": "adtrans",
            "FAULT_COMPUTATION_EPOCH": "7",
            "FAULT_DELTA_MS": "10",
        }
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=8, environ=base)

        base["FAULT_COMPUTATION_EPOCH"] = "3"
        base["FAULT_DELTA_MS"] = "0"
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=4, t=1, layers=8, environ=base)

    def test_byzantine_requires_complete_adtrans_configuration(self):
        config = FaultConfig.from_env(
            n=4,
            t=1,
            layers=8,
            environ={
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "adtrans",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_ATTACK_INDEX": "0",
            },
        )
        self.assertEqual(config.attack_index, 0)
        self.assertIsNone(config.delta_ms)

        for bad in (
            {"FAULT_MODE": "byzantine"},
            {
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "adtrans",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_ATTACK_INDEX": "-1",
            },
            {
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "adtrans",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_ATTACK_INDEX": "0",
                "FAULT_DELTA_MS": "1",
            },
        ):
            with self.assertRaises(FaultConfigurationError):
                FaultConfig.from_env(n=4, t=1, layers=8, environ=bad)

    def test_only_selected_c3_source_delays_once(self):
        env = {
            "FAULT_MODE": "delay",
            "FAULT_TARGET": "adtrans",
            "FAULT_COMPUTATION_EPOCH": "3",
            "FAULT_DELTA_MS": "1",
        }
        selected = ADMPCFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=3,
            local_party_id=3,
            environ=env,
        )
        other_party = ADMPCFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=3,
            local_party_id=2,
            environ=env,
        )
        other_epoch = ADMPCFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=2,
            local_party_id=3,
            environ=env,
        )

        self.assertTrue(selected.should_delay_adtrans())
        self.assertFalse(other_party.should_delay_adtrans())
        self.assertFalse(other_epoch.should_delay_adtrans())
        self.assertFalse(selected.observes_target_destination())

        destination = ADMPCFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=4,
            local_party_id=0,
            environ=env,
        )
        self.assertTrue(destination.observes_target_destination())
        self.assertTrue(asyncio.run(selected.delay_adtrans_if_needed()))
        with self.assertRaises(RuntimeError):
            asyncio.run(selected.delay_adtrans_if_needed())

    def test_only_selected_source_mutates_and_destination_forces_verification(self):
        env = {
            "FAULT_MODE": "byzantine",
            "FAULT_TARGET": "adtrans",
            "FAULT_COMPUTATION_EPOCH": "3",
            "FAULT_ATTACK_INDEX": "1",
        }
        selected = ADMPCFaultController.from_env(
            n=4, t=1, layers=8, physical_layer_id=3, local_party_id=3,
            environ=env,
        )
        honest = ADMPCFaultController.from_env(
            n=4, t=1, layers=8, physical_layer_id=3, local_party_id=2,
            environ=env,
        )
        destination = ADMPCFaultController.from_env(
            n=4, t=1, layers=8, physical_layer_id=4, local_party_id=0,
            environ=env,
        )

        self.assertTrue(selected.should_mutate_adtrans())
        self.assertEqual(selected.begin_adtrans_mutation(3), 1)
        with self.assertRaises(RuntimeError):
            selected.begin_adtrans_mutation(3)
        self.assertFalse(honest.should_mutate_adtrans())
        self.assertTrue(destination.requires_adtrans_verification(3))
        self.assertFalse(destination.requires_adtrans_verification(2))

    def test_attack_index_is_checked_against_runtime_batch(self):
        controller = ADMPCFaultController.from_env(
            n=4,
            t=1,
            layers=8,
            physical_layer_id=3,
            local_party_id=3,
            environ={
                "FAULT_MODE": "byzantine",
                "FAULT_TARGET": "adtrans",
                "FAULT_COMPUTATION_EPOCH": "3",
                "FAULT_ATTACK_INDEX": "4",
            },
        )
        with self.assertRaises(FaultConfigurationError):
            controller.begin_adtrans_mutation(4)

    def test_figure10_attack_uses_source_epochs_three_and_four(self):
        env = {
            "FAULT_MODE": "figure10-attack",
            "FAULT_TARGET": "adtrans",
            "FAULT_DELAY_SOURCE_EPOCH": "3",
            "FAULT_ADTRANS_SOURCE_EPOCH": "4",
            "FAULT_DELTA_MS": "10000",
            "FAULT_ATTACK_INDEX": "0",
        }
        config = FaultConfig.from_env(n=16, t=5, layers=8, environ=env)
        self.assertEqual(config.delay_source_epoch, 3)
        self.assertEqual(config.adtrans_source_epoch, 4)

        delay_source = ADMPCFaultController.from_env(
            n=16, t=5, layers=8, physical_layer_id=3, local_party_id=11,
            environ=env,
        )
        attack_source = ADMPCFaultController.from_env(
            n=16, t=5, layers=8, physical_layer_id=4, local_party_id=11,
            environ=env,
        )
        attack_destination = ADMPCFaultController.from_env(
            n=16, t=5, layers=8, physical_layer_id=5, local_party_id=0,
            environ=env,
        )
        self.assertTrue(delay_source.should_delay_adtrans())
        self.assertFalse(delay_source.should_mutate_adtrans())
        self.assertTrue(attack_source.should_mutate_adtrans())
        self.assertTrue(attack_destination.observes_attack_destination())
        self.assertTrue(attack_destination.requires_adtrans_verification(11))

    def test_figure10_attack_rejects_wrong_schedule_delay_or_legacy_epochs(self):
        base = {
            "FAULT_MODE": "figure10-attack",
            "FAULT_TARGET": "adtrans",
            "FAULT_DELAY_SOURCE_EPOCH": "3",
            "FAULT_ADTRANS_SOURCE_EPOCH": "5",
            "FAULT_DELTA_MS": "10000",
            "FAULT_ATTACK_INDEX": "0",
        }
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=16, t=5, layers=8, environ=base)
        wrong_consecutive = dict(
            base,
            FAULT_DELAY_SOURCE_EPOCH="2",
            FAULT_ADTRANS_SOURCE_EPOCH="3",
        )
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(
                n=16, t=5, layers=8, environ=wrong_consecutive
            )
        wrong_delay = dict(base, FAULT_ADTRANS_SOURCE_EPOCH="4", FAULT_DELTA_MS="9999")
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=16, t=5, layers=8, environ=wrong_delay)
        legacy = dict(base)
        legacy["FAULT_ADTRANS_SOURCE_EPOCH"] = "4"
        legacy["FAULT_COMPUTATION_EPOCH"] = "3"
        with self.assertRaises(FaultConfigurationError):
            FaultConfig.from_env(n=16, t=5, layers=8, environ=legacy)

    def test_outgoing_copy_changes_one_value_without_mutating_inputs(self):
        values = [10, 20, 30]
        rand_values = [1, 2, 3, 4]
        w_list = ["w0", "w1"]
        forked_values, forked_rand, forked_w = build_adtrans_outgoing_copy(
            values=values,
            rand_values=rand_values,
            w_list=w_list,
            attack_index=1,
            delta=BYZANTINE_DELTA,
        )

        self.assertEqual(forked_values, [10, 21, 30])
        self.assertEqual(values, [10, 20, 30])
        self.assertEqual(forked_rand, rand_values)
        self.assertEqual(forked_w, w_list)
        self.assertIsNot(forked_values, values)
        self.assertIsNot(forked_rand, rand_values)
        self.assertIsNot(forked_w, w_list)

    def test_post_decode_validation_catches_ignored_tail_dealer(self):
        class LinearPolynomial:
            def __call__(self, x):
                return 2 * x + 3

        point = lambda dealer: dealer + 1
        shares = [5, 7, 9, 12]
        self.assertEqual(
            find_inconsistent_dealers(
                LinearPolynomial(), shares, [0, 1, 2, 3], point
            ),
            [3],
        )


if __name__ == "__main__":
    unittest.main()
