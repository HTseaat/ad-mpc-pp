from pathlib import Path
import stat
import unittest


ROOT = Path(__file__).resolve().parents[2]
UNIFIED = ROOT / "unified"
README = ROOT / "README.md"

WRAPPERS = {
    "run_figure10_admpc_accum_local.sh": "admpc-accum",
    "run_figure10_continuum_accum_local.sh": "continuum-accum",
    "run_figure10_dumbo_accum_local.sh": "dumbo-accum",
    "run_figure10_admpc_attack_local.sh": "admpc-attack",
    "run_figure10_continuum_attack_local.sh": "continuum-attack",
}


class Figure10LocalWrapperTests(unittest.TestCase):
    def test_public_wrappers_are_parameterless_and_map_one_to_one(self):
        for filename, case_name in WRAPPERS.items():
            path = UNIFIED / filename
            text = path.read_text(encoding="utf-8")
            self.assertIn("[[ $# -ne 0 ]]", text)
            self.assertIn(
                f"exec /opt/unified/run_figure10_local_case.sh {case_name}", text
            )

    def test_helper_freezes_the_paper_configuration_and_hidden_switches(self):
        text = (UNIFIED / "run_figure10_local_case.sh").read_text(
            encoding="utf-8"
        )
        for assignment in (
            "n=16",
            "t=5",
            "depth=6",
            "width=100",
            "layers=$((depth + 2))",
            "total_cm=$((depth * width / 2))",
            "export ZMQ_AUTH_MODE=curve",
            "export ADTRANS_ALG4_PER_ITEM=0",
            'export CIRCUIT_WIDTH="$width"',
        ):
            self.assertIn(assignment, text)
        self.assertIn('dumbo_observation_timeout=600', text)
        self.assertIn('"$total_cm" fault-accumulation "$depth"', text)

    def test_scripts_are_executable(self):
        for filename in ["run_figure10_local_case.sh", *WRAPPERS]:
            mode = (UNIFIED / filename).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, filename)

    def test_readme_lists_each_curve_without_arguments(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("### 2.4 Figure 10: GOD under adversarial faults", text)
        for filename in WRAPPERS:
            self.assertIn(f"./unified/{filename}\n", text)


if __name__ == "__main__":
    unittest.main()
