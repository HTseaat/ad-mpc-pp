import json
from pathlib import Path
import tempfile
import unittest

from unified.distributed.analyze_admpc_adversarial_case import analyze_case


class DistributedADMPCAdversarialCaseTests(unittest.TestCase):
    def _write_case(self, case_dir: Path, scenario: str) -> None:
        n, layers = 4, 8
        log_dir = case_dir / "logs"
        log_dir.mkdir()
        mode = "delay" if scenario == "admpc-delay" else "byzantine"
        for layer in range(layers):
            for local_id in range(n):
                config = {
                    "schema": "admpc-fault-v1",
                    "event": "config",
                    "protocol": "admpc",
                    "mode": mode,
                    "target": "adtrans",
                    "computation_epoch": 3,
                    "delta_ms": 2000 if mode == "delay" else None,
                    "attack_index": None if mode == "delay" else 0,
                    "physical_layer_id": layer,
                    "local_party_id": local_id,
                    "global_party_id": layer * n + local_id,
                    "selected_local_ids": [3],
                    "wall_time": 100.0,
                }
                lines = [
                    "ADMPC start time: 100.0",
                    "CURVE channel ready: peers=31 channel_setup_ms=1.0",
                    "FAULT_EVENT " + json.dumps(config),
                    f"layer ID: {layer} layer_time: {layer + local_id / 10 + 1}",
                ]
                if layer == 3 and local_id == 3:
                    if mode == "delay":
                        for event, extra in (
                            ("delay_scheduled", {"components": ["adtrans"]}),
                            (
                                "delay_released",
                                {"components": ["adtrans"], "actual_delay_ms": 2000.5},
                            ),
                        ):
                            lines.append(
                                "FAULT_EVENT "
                                + json.dumps({**config, "event": event, **extra})
                            )
                    else:
                        lines.append(
                            "FAULT_EVENT "
                            + json.dumps(
                                {
                                    **config,
                                    "event": "byzantine_mutation",
                                    "component": "adtrans",
                                    "attack_style": "outgoing_share_fork",
                                    "outgoing_copy": True,
                                    "acss_resharing_recomputed": True,
                                    "commitment_recomputed": True,
                                    "mask_recomputed": True,
                                    "consistency_proof_recomputed": True,
                                }
                            )
                        )
                if layer == 4:
                    if mode == "byzantine":
                        lines.append(
                            "FAULT_EVENT "
                            + json.dumps(
                                {
                                    **config,
                                    "event": "adtrans_verification",
                                    "component": "adtrans",
                                    "dealer_local_id": 3,
                                    "accepted": True,
                                    "share_binding_valid": True,
                                    "consistency_proof_valid": True,
                                    "legacy_fast_path_overridden": True,
                                }
                            )
                        )
                    lines.append(
                        "FAULT_EVENT "
                        + json.dumps(
                            {
                                **config,
                                "event": "adtrans_acss_complete",
                                "dealer_local_ids": [0, 1, 2, 3],
                            }
                        )
                    )
                    if mode == "byzantine":
                        lines.append(
                            "FAULT_EVENT "
                            + json.dumps(
                                {
                                    **config,
                                    "event": "adtrans_robust_filter",
                                    "component": "adtrans",
                                    "all_candidates_checked": True,
                                    "candidate_dealers": [0, 1, 2, 3],
                                    "corrupted_dealers_detected": [3],
                                    "post_decode_mismatch_dealers": [3],
                                    "error_dealers": [3],
                                    "filtered_dealers": [0, 1, 2],
                                    "matching_randomness_dealers": [0, 1, 2],
                                    "decoder_error_dealers": [],
                                }
                            )
                        )
                    lines.append(
                        "FAULT_EVENT "
                        + json.dumps(
                            {
                                **config,
                                "event": "adtrans_common_subset",
                                "dealer_local_ids": (
                                    [0, 1, 2, 3] if mode == "delay" else [0, 1, 2]
                                ),
                                "corrupted_dealers_in_subset": (
                                    [3] if mode == "delay" else []
                                ),
                            }
                        )
                    )
                if layer == layers - 1:
                    lines.append(
                        f"my_send_id: {layer * n + local_id} exec_time: 99.0"
                    )
                lines.append(
                    "CURVE authentication failures: 0; invalid metadata: 0; "
                    "identity spoofing events: 0"
                )
                (log_dir / f"node{local_id + 1}_cont{layer + 1}.log").write_text(
                    "\n".join(lines) + "\n", encoding="utf-8"
                )

    def test_delay_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            self._write_case(case_dir, "admpc-delay")
            summary = analyze_case(
                case_dir=case_dir,
                scenario="admpc-delay",
                n=4,
                t=1,
                layers=8,
                computation_epoch=3,
                delay_ms=2000,
                attack_index=None,
                output_dir=case_dir,
            )
            self.assertTrue(summary["success"], summary["errors"])
            self.assertAlmostEqual(summary["final_layer_latency_sec"], 8.3)

    def test_byzantine_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp)
            self._write_case(case_dir, "admpc-byzantine")
            summary = analyze_case(
                case_dir=case_dir,
                scenario="admpc-byzantine",
                n=4,
                t=1,
                layers=8,
                computation_epoch=3,
                delay_ms=None,
                attack_index=0,
                output_dir=case_dir,
            )
            self.assertTrue(summary["success"], summary["errors"])
            self.assertEqual(summary["counts"]["adtrans_robust_filter"], 4)


if __name__ == "__main__":
    unittest.main()
