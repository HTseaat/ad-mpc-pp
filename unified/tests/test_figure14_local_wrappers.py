from pathlib import Path
import stat
import unittest


ROOT = Path(__file__).resolve().parents[2]
UNIFIED = ROOT / "unified"
README = ROOT / "README.md"

WRAPPERS = {
    "run_figure14_admpc_local.sh": "admpc",
    "run_figure14_continuum_local.sh": "continuum",
    "run_figure14_dumbo_mpc_local.sh": "dumbo-mpc",
}


class Figure14LocalWrapperTests(unittest.TestCase):
    def test_public_wrappers_only_expose_n_t_and_d(self):
        for filename, case_name in WRAPPERS.items():
            text = (UNIFIED / filename).read_text(encoding="utf-8")
            self.assertIn('echo "Usage: $0 <n> <t> <d>"', text)
            self.assertIn("[[ $# -ne 3 ]]", text)
            self.assertIn(
                f'exec /opt/unified/run_figure14_local_case.sh {case_name} "$@"',
                text,
            )

    def test_helper_fixes_the_mixed_circuit_configuration(self):
        text = (UNIFIED / "run_figure14_local_case.sh").read_text(
            encoding="utf-8"
        )
        for setting in (
            "width=100",
            "layers=$((depth + 2))",
            "total_cm=$((depth * width / 2))",
            'export CIRCUIT_WIDTH="$width"',
            "export ZMQ_AUTH_MODE=curve",
            "export ADTRANS_ALG4_PER_ITEM=0",
            'admpc "$n" "$t" "$layers" "$total_cm"',
            '"$n" "$t" "$layers" "$total_cm" mixed',
            '"$n" "$t" "$total_cm" full "$depth"',
        ):
            self.assertIn(setting, text)

    def test_scripts_are_executable(self):
        for filename in ["run_figure14_local_case.sh", *WRAPPERS]:
            mode = (UNIFIED / filename).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, filename)

    def test_readme_lists_the_three_commands_and_parameters(self):
        readme = README.read_text(encoding="utf-8")
        section = readme.split("### 2.6 Figure 14", 1)[1].split("## 3.", 1)[0]
        for filename in WRAPPERS:
            self.assertIn(f"./unified/{filename}", section)
        self.assertIn("<n> <t> <d>", section)
        self.assertIn("mixed circuit", section)
        self.assertIn("`w=100`", section)
        self.assertNotIn("Dumbo-MPC local test (AsyRanTriGen path)", readme)


if __name__ == "__main__":
    unittest.main()
