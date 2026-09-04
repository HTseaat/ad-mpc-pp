from pathlib import Path
import stat
import unittest


ROOT = Path(__file__).resolve().parents[2]
UNIFIED = ROOT / "unified"
README = ROOT / "README.md"

WRAPPERS = {
    "run_figure11_admpc_local.sh": "admpc",
    "run_figure11_continuum_local.sh": "continuum",
    "run_figure11_continuum_coarse_local.sh": "continuum-coarse",
    "run_figure11_continuum_static_local.sh": "continuum-static",
    "run_figure11_bgw_ampc_local.sh": "bgw-ampc",
}


class Figure11LocalWrapperTests(unittest.TestCase):
    def test_public_wrappers_only_expose_n_and_t(self):
        for filename, case_name in WRAPPERS.items():
            text = (UNIFIED / filename).read_text(encoding="utf-8")
            self.assertIn('echo "Usage: $0 <n> <t>"', text)
            self.assertIn("[[ $# -ne 2 ]]", text)
            self.assertIn(
                f'exec /opt/unified/run_figure11_local_case.sh {case_name} "$@"',
                text,
            )

    def test_helper_fixes_the_figure11_modes(self):
        text = (UNIFIED / "run_figure11_local_case.sh").read_text(
            encoding="utf-8"
        )
        for setting in (
            "shuffle_k=128",
            "switch_layers=49",
            "export SHUFFLE_MODE=iterated",
            "export SHUFFLE_HANDOFF_INTERVAL=1",
            "export SHUFFLE_HANDOFF_INTERVAL=5",
            "export SHUFFLE_HANDOFF_INTERVAL=static",
            "export BGW_UNBATCHED_VERIFY=0",
            "export BGW_BATCH_UNBATCHED_PROD_VERIFY=1",
        ):
            self.assertIn(setting, text)

    def test_scripts_are_executable(self):
        for filename in ["run_figure11_local_case.sh", *WRAPPERS]:
            mode = (UNIFIED / filename).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, filename)

    def test_local_readme_uses_only_named_wrappers(self):
        readme = README.read_text(encoding="utf-8")
        section = readme.split("### 2.5 Figure 11", 1)[1].split("### 2.6", 1)[0]
        for filename in WRAPPERS:
            self.assertIn(f"./unified/{filename}", section)
        self.assertNotIn("SHUFFLE_MODE", section)
        self.assertNotIn("SHUFFLE_HANDOFF_INTERVAL", section)
        self.assertNotIn("BGW_UNBATCHED_VERIFY", section)


if __name__ == "__main__":
    unittest.main()
