import unittest

from beaver.fault_accumulation import (
    FaultAccumulationConfig,
    FaultAccumulationConfigurationError,
    FaultAccumulationController,
)


class FaultAccumulationConfigTests(unittest.TestCase):
    def test_default_is_strict_noop(self):
        config = FaultAccumulationConfig.from_env(n=16, t=5, layers=8, environ={})
        self.assertFalse(config.enabled)
        self.assertEqual(config.dynamic_silent_local_ids, ())
        self.assertEqual(config.static_new_silent_local_ids(1), ())

    def test_none_rejects_stale_parameters(self):
        with self.assertRaises(FaultAccumulationConfigurationError):
            FaultAccumulationConfig.from_env(
                n=16,
                t=5,
                layers=8,
                environ={"FAULT_ACCUMULATION_COUNT": "2"},
            )

    def test_figure10_dynamic_schedule_is_t_per_committee(self):
        config = FaultAccumulationConfig.from_env(
            n=16,
            t=5,
            layers=8,
            environ={"FAULT_ACCUMULATION_MODE": "silent"},
        )
        self.assertEqual(config.count, 5)
        self.assertEqual(config.dynamic_silent_local_ids, (11, 12, 13, 14, 15))

        for physical_layer in range(1, 7):
            selected = FaultAccumulationController(
                config=config,
                protocol="continuum",
                local_party_id=11,
                physical_layer_id=physical_layer,
            )
            honest = FaultAccumulationController(
                config=config,
                protocol="continuum",
                local_party_id=10,
                physical_layer_id=physical_layer,
            )
            self.assertTrue(selected.continuum_should_be_silent())
            self.assertFalse(honest.continuum_should_be_silent())

    def test_continuum_input_and_output_committees_are_not_silenced(self):
        env = {"FAULT_ACCUMULATION_MODE": "silent"}
        for layer in (0, 7):
            controller = FaultAccumulationController.from_env(
                protocol="continuum",
                n=16,
                t=5,
                layers=8,
                local_party_id=15,
                physical_layer_id=layer,
                environ=env,
            )
            self.assertFalse(controller.continuum_should_be_silent())

    def test_figure10_static_schedule_accumulates_t_per_epoch(self):
        config = FaultAccumulationConfig.from_env(
            n=16,
            t=5,
            layers=8,
            environ={"FAULT_ACCUMULATION_MODE": "silent"},
        )
        self.assertEqual(config.static_new_silent_local_ids(1), (11, 12, 13, 14, 15))
        self.assertEqual(config.static_new_silent_local_ids(2), (6, 7, 8, 9, 10))
        self.assertEqual(config.static_new_silent_local_ids(3), (1, 2, 3, 4, 5))
        self.assertEqual(config.static_first_silent_epoch(15), 1)
        self.assertEqual(config.static_first_silent_epoch(10), 2)
        self.assertEqual(config.static_first_silent_epoch(5), 3)

        node_10 = FaultAccumulationController(
            config=config, protocol="dumbo-mpc", local_party_id=10
        )
        self.assertFalse(node_10.dumbo_should_stop_before_layer(0))
        self.assertTrue(node_10.dumbo_should_stop_before_layer(1))
        self.assertFalse(node_10.dumbo_should_stop_before_layer(2))

    def test_invalid_or_conflicting_configuration_fails_closed(self):
        invalid_envs = (
            {"FAULT_ACCUMULATION_MODE": "silent", "FAULT_ACCUMULATION_COUNT": "0"},
            {"FAULT_ACCUMULATION_MODE": "silent", "FAULT_ACCUMULATION_COUNT": "6"},
            {"FAULT_ACCUMULATION_MODE": "silent", "FAULT_ACCUMULATION_START_EPOCH": "0"},
            {"FAULT_ACCUMULATION_MODE": "silent", "FAULT_MODE": "delay"},
        )
        for env in invalid_envs:
            with self.subTest(env=env):
                with self.assertRaises(FaultAccumulationConfigurationError):
                    FaultAccumulationConfig.from_env(
                        n=16, t=5, layers=8, environ=env
                    )


if __name__ == "__main__":
    unittest.main()
