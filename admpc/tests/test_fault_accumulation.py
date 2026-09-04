import unittest

from adkg.fault_accumulation import (
    ADMPCFaultAccumulationController,
    FaultAccumulationConfig,
    FaultAccumulationConfigurationError,
)


class FaultAccumulationTests(unittest.TestCase):
    def test_default_is_noop(self):
        config = FaultAccumulationConfig.from_env(
            n=16, t=5, layers=8, environ={}
        )
        self.assertFalse(config.enabled)
        self.assertEqual(config.silent_local_ids, ())

    def test_figure10_uses_t_silent_parties_per_computation_epoch(self):
        env = {"FAULT_ACCUMULATION_MODE": "silent"}
        config = FaultAccumulationConfig.from_env(
            n=16, t=5, layers=8, environ=env
        )
        self.assertEqual(config.count, 5)
        self.assertEqual(config.silent_local_ids, (11, 12, 13, 14, 15))

        for layer in range(1, 7):
            selected = ADMPCFaultAccumulationController.from_env(
                n=16,
                t=5,
                layers=8,
                physical_layer_id=layer,
                local_party_id=11,
                environ=env,
            )
            honest = ADMPCFaultAccumulationController.from_env(
                n=16,
                t=5,
                layers=8,
                physical_layer_id=layer,
                local_party_id=10,
                environ=env,
            )
            self.assertTrue(selected.should_be_silent())
            self.assertFalse(honest.should_be_silent())

    def test_input_and_output_committees_are_not_silent(self):
        env = {"FAULT_ACCUMULATION_MODE": "silent"}
        for layer in (0, 7):
            controller = ADMPCFaultAccumulationController.from_env(
                n=16,
                t=5,
                layers=8,
                physical_layer_id=layer,
                local_party_id=15,
                environ=env,
            )
            self.assertFalse(controller.should_be_silent())

    def test_invalid_and_conflicting_settings_fail_closed(self):
        invalid = (
            {"FAULT_ACCUMULATION_COUNT": "5"},
            {"FAULT_ACCUMULATION_MODE": "silent", "FAULT_ACCUMULATION_COUNT": "0"},
            {"FAULT_ACCUMULATION_MODE": "silent", "FAULT_ACCUMULATION_COUNT": "6"},
            {"FAULT_ACCUMULATION_MODE": "silent", "FAULT_MODE": "delay"},
        )
        for env in invalid:
            with self.subTest(env=env):
                with self.assertRaises(FaultAccumulationConfigurationError):
                    FaultAccumulationConfig.from_env(
                        n=16, t=5, layers=8, environ=env
                    )


if __name__ == "__main__":
    unittest.main()
