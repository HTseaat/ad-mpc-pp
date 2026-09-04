from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def test_figure8_runners_separate_normal_and_communication_modes():
    local_case = _read("unified/run_figure8_local_case.sh")
    communication_case = _read("unified/run_figure8_communication_case.sh")
    case_runner = _read("unified/run_figure8_one_layer_case.sh")
    admpc = _read("unified/run_figure8_admpc_local.sh")
    noagg = _read("unified/run_figure8_noagg_local.sh")
    aggtrans = _read("unified/run_figure8_aggtrans_local.sh")
    admpc_communication = _read(
        "unified/run_figure8_admpc_communication_local.sh"
    )
    noagg_communication = _read(
        "unified/run_figure8_noagg_communication_local.sh"
    )
    aggtrans_communication = _read(
        "unified/run_figure8_aggtrans_communication_local.sh"
    )
    scripts = (
        local_case + communication_case + case_runner + admpc + noagg
        + aggtrans + admpc_communication + noagg_communication
        + aggtrans_communication
    )
    assert "admpc-batchrand" not in scripts
    assert "ADTRANS_ALG4_PER_ITEM:-" not in scripts
    assert "export ADTRANS_ALG4_PER_ITEM=0" in local_case
    assert "export ADTRANS_ALG4_PER_ITEM=1" in case_runner
    assert "export AGG_KZG_V2=1" in case_runner
    assert "export ZMQ_AUTH_MODE=curve" in case_runner
    assert "admpc-linear" in admpc
    assert "continuum-noagg" in noagg
    assert "continuum-aggtrans" in aggtrans
    assert "admpc-linear" in admpc_communication
    assert "continuum-noagg" in noagg_communication
    assert "continuum-aggtrans" in aggtrans_communication


def test_figure9_runners_separate_normal_and_communication_modes():
    local_case = _read("unified/run_figure9_local_case.sh")
    communication_case = _read("unified/run_figure9_communication_case.sh")
    case_runner = _read("unified/run_figure9_one_layer_case.sh")
    admpc = _read("unified/run_figure9_admpc_local.sh")
    batchmul = _read("unified/run_figure9_batchmul_local.sh")
    bgw = _read("unified/run_figure9_bgw_aggtrans_local.sh")
    admpc_communication = _read(
        "unified/run_figure9_admpc_communication_local.sh"
    )
    batchmul_communication = _read(
        "unified/run_figure9_batchmul_communication_local.sh"
    )
    bgw_communication = _read(
        "unified/run_figure9_bgw_aggtrans_communication_local.sh"
    )
    scripts = (
        local_case + communication_case + case_runner + admpc + batchmul
        + bgw + admpc_communication + batchmul_communication
        + bgw_communication
    )
    assert "admpc-batchrand" not in scripts
    assert "ADTRANS_ALG4_PER_ITEM:-" not in scripts
    assert "export ADTRANS_ALG4_PER_ITEM=0" in local_case
    assert "export ADTRANS_ALG4_PER_ITEM=1" in case_runner
    assert "export AGG_KZG_V2=1" in case_runner
    assert "export ZMQ_AUTH_MODE=curve" in case_runner
    assert "admpc-nonlinear" in admpc
    assert "continuum-batchmul" in batchmul
    assert "bgw-aggtrans" in bgw
    assert "admpc-nonlinear" in admpc_communication
    assert "continuum-batchmul" in batchmul_communication
    assert "bgw-aggtrans" in bgw_communication
    assert "export BGW_UNBATCHED_VERIFY=1" in case_runner


def test_final_summaries_do_not_restore_or_add_protocol_phases():
    figure8 = _read("unified/summarize_figure8_communication.py")
    figure9 = _read("unified/summarize_figure9_communication.py")
    forbidden = (
        "algorithm4_per_item_public_field_restoration",
        "admpc_batchrand_separate",
        "measured_batchrand",
    )
    for marker in forbidden:
        assert marker not in figure8
        assert marker not in figure9
