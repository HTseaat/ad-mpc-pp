import json
from pathlib import Path
import tempfile
import unittest

from unified.distributed.analyze_adversarial_case import analyze_case, exclusion_keys


class DistributedAdversarialCaseTests(unittest.TestCase):
    def test_duplicate_exclusion_is_one_logical_payload(self):
        event = {
            "event": "batchmul_commitment_excluded",
            "physical_layer_id": 5,
            "local_party_id": 0,
            "dealer_local_id": 3,
            "left_commitment_digest": "left",
            "right_commitment_digest": "right",
        }
        identities, unique = exclusion_keys([event, dict(event)], "batchmul")
        self.assertEqual(identities, {(5, 0, 3)})
        self.assertEqual(unique, {(5, 0, 3, "left", "right")})

    def test_delay_case_uses_distributed_logs_and_final_layer_time(self):
        n, t, layers = 4, 1, 8
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            log_dir = case_dir / "logs"
            log_dir.mkdir()
            selected = [3]
            for layer in range(layers):
                for local_id in range(n):
                    config = {
                        "schema": "continuum-fault-v1",
                        "event": "config",
                        "protocol": "continuum",
                        "mode": "delay",
                        "target": "handoff",
                        "computation_epoch": 3,
                        "delta_ms": 2000,
                        "attack_index": None,
                        "physical_layer_id": layer,
                        "local_party_id": local_id,
                        "selected_local_ids": selected,
                        "component_epochs": {"aggtrans": None, "batchmul": None},
                        "wall_time": 100.0,
                    }
                    lines = [
                        "ADMPC start time: 100.0",
                        "CURVE channel ready: peers=7 channel_setup_ms=1.0",
                        "FAULT_EVENT " + json.dumps(config),
                        f"layer ID: {layer} layer_time: {layer + local_id / 10 + 1}",
                    ]
                    if layer == 3 and local_id == 3:
                        for event, extra in (
                            ("delay_scheduled", {}),
                            ("delay_released", {"actual_delay_ms": 2000.5}),
                        ):
                            payload = {**config, "event": event, **extra}
                            lines.append("FAULT_EVENT " + json.dumps(payload))
                    if layer == 4:
                        for component in ("aggtrans", "batchmul"):
                            payload = {
                                **config,
                                "event": f"{component}_common_subset",
                                "component": component,
                                "dealers": [0, 1, 2],
                                "delayed_dealers_in_subset": [],
                                "corrupted_dealers_in_subset": [],
                            }
                            lines.append("FAULT_EVENT " + json.dumps(payload))
                    if layer == layers - 1:
                        lines.extend(
                            [
                                f"my_send_id: {layer * n + local_id} exec_time: 99.0",
                                f"layer ID: {layer} reconstructed trans_values length: 10",
                            ]
                        )
                    lines.append(
                        "CURVE authentication failures: 0; invalid metadata: 0; identity spoofing events: 0"
                    )
                    (log_dir / f"node{local_id + 1}_cont{layer + 1}.log").write_text(
                        "\n".join(lines) + "\n", encoding="utf-8"
                    )

            summary = analyze_case(
                case_dir=case_dir,
                scenario="continuum-delay",
                n=n,
                t=t,
                layers=layers,
                computation_epoch=3,
                batchmul_epoch=None,
                delay_ms=2000,
                attack_index=None,
                output_dir=case_dir,
            )
            self.assertTrue(summary["success"], summary["errors"])
            self.assertAlmostEqual(summary["final_layer_latency_sec"], 8.3)
            self.assertTrue((case_dir / "layer-trace.tsv").is_file())


if __name__ == "__main__":
    unittest.main()
