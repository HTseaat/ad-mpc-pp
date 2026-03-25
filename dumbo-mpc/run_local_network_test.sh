#!/bin/bash
set -e

usage() {
    echo "Usage:"
    echo "  $0 ad-mpc2|ad-mpc2-linear|ad-mpc2-nonlinear <committee_size> <layers> <total_cm>"
    echo "  $0 <task_name> <committee_size> <k>"
    echo "  $0 asy-triple <committee_size> <k> [full|drop-epoch4] [layers]"
    echo "Valid task names: ad-mpc2, ad-mpc2-linear, ad-mpc2-nonlinear, asy-random, asy-triple, dumbo-mpc, opt-triple, dyn-transfer, dyn-aggtransfer, dyn-pvtransfer, bat-multiplication, bat-pvmul, yoso-rbc, yoso-gather, yoso-gradedgather"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

TASK_NAME=$1
shift

case "$TASK_NAME" in
    "ad-mpc2"|"ad-mpc2-linear"|"ad-mpc2-nonlinear")
        if [ $# -lt 3 ]; then
            echo "Error: ${TASK_NAME} requires 3 arguments"
            usage
        fi
        N=$1
        LAYERS=$2
        TOTAL_CM=$3

        case "$TASK_NAME" in
            "ad-mpc2")
                MODULE="scripts/admpc2_dynamic_run.py"
                ;;
            "ad-mpc2-linear")
                MODULE="scripts/admpc2_dynamic_linear_run.py"
                ;;
            "ad-mpc2-nonlinear")
                MODULE="scripts/admpc2_dynamic_nonlinear_run.py"
                ;;
        esac

        echo "Running $(basename "${MODULE}")"
        cd ./dumbo-mpc/AsyRanTriGen
        ./scripts/local_admpc_test.sh "${MODULE}" "${N}" "${LAYERS}" "${TOTAL_CM}"
        ;;

    "asy-random")
        if [ $# -lt 2 ]; then
            echo "Error: asy-random requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running run_random.py"
        cd ./dumbo-mpc/AsyRanTriGen
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh scripts/run_random.py "${N}" "${K}"
        ;;
    
    "asy-triple")
        if [ $# -lt 2 ]; then
            echo "Error: asy-triple requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        DUMBO_MODE=${3:-full}
        LAYERS=${4:-10}
        case "$DUMBO_MODE" in
            full|drop-epoch4) ;;
            *)
                echo "Error: invalid asy-triple mode '${DUMBO_MODE}'. Expected 'full' or 'drop-epoch4'."
                usage
                ;;
        esac
        if ! [[ "$LAYERS" =~ ^[0-9]+$ ]] || [ "$LAYERS" -le 0 ]; then
            echo "Error: layers must be a positive integer, got '${LAYERS}'."
            usage
        fi
        echo "Running run_beaver_triple.py (mode=${DUMBO_MODE}, layers=${LAYERS})"
        cd ./dumbo-mpc/AsyRanTriGen
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh scripts/run_beaver_triple.py "${N}" "${K}" "${DUMBO_MODE}" "${LAYERS}"
        ;;
    
    "dumbo-mpc")
        if [ $# -lt 2 ]; then
            echo "Error: dumbo-mpc requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running run_dual_mode.py"
        cd ./dumbo-mpc/dualmode
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh scripts/run_dual_mode.py "${N}" "${K}"
        ;;
    
    "opt-triple")
        if [ $# -lt 2 ]; then
            echo "Error: opt-triple requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running optrantrigen.py"
        cd ./dumbo-mpc/OptRanTriGen
        # python scripts/init_batchsize_ip.py --N ${N} --k ${k}
        ./scripts/local_test.sh optimizedhbmpc/optrantrigen.py "${N}" "${K}"
        ;;
    

    "dyn-transfer")
        if [ $# -lt 2 ]; then
            echo "Error: dyn-transfer requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running dynamic transfer"
        cd ./dumbo-mpc/AsyRanTriGen
        # 1) offline setup to generate initial commitments / shares
        python scripts/setup_transfer.py --N "${N}" --k "${K}"
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_transfer.py "${N}" "${K}"
        ;;
    
    "dyn-aggtransfer")
        if [ $# -lt 2 ]; then
            echo "Error: dyn-aggtransfer requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running dynamic transfer"
        cd ./dumbo-mpc/AsyRanTriGen
        # 1) offline setup to generate initial commitments / shares
        python scripts/setup_transfer.py --N "${N}" --k "${K}"
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_transfer.py "${N}" "${K}"
        ;;
    
    "dyn-pvtransfer")
        if [ $# -lt 2 ]; then
            echo "Error: dyn-pvtransfer requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running dynamic transfer"
        cd ./dumbo-mpc/AsyRanTriGen
        # 1) offline setup to generate initial commitments / shares
        python scripts/setup_transfer.py --N "${N}" --k "${K}"
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_pvtransfer.py "${N}" "${K}"
        ;;
    
    "bat-multiplication")
        if [ $# -lt 2 ]; then
            echo "Error: bat-multiplication requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running batch multiplication"
        cd ./dumbo-mpc/AsyRanTriGen
        # 1) offline setup to generate initial commitments / shares
        python scripts/setup_batch_multiplication.py --N "${N}" --k "${K}"
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_batch_multiplication.py "${N}" "${K}"
        ;;
    
    "bat-pvmul")
        if [ $# -lt 2 ]; then
            echo "Error: bat-pvmul requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running batch multiplication"
        cd ./dumbo-mpc/AsyRanTriGen
        # 1) offline setup to generate initial commitments / shares
        python scripts/setup_batch_multiplication.py --N "${N}" --k "${K}"
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_batch_pvmultiplication.py "${N}" "${K}"
        ;;
    
    "yoso-rbc")
        if [ $# -lt 2 ]; then
            echo "Error: yoso-rbc requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running batch multiplication"
        cd ./dumbo-mpc/AsyRanTriGen
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_yosorbc.py "${N}" "${K}"
        ;;
    
    "yoso-gather")
        if [ $# -lt 2 ]; then
            echo "Error: yoso-gather requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running yoso gather"
        cd ./dumbo-mpc/AsyRanTriGen
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_gather.py "${N}" "${K}"
        ;;  
    
    "yoso-gradedgather")
        if [ $# -lt 2 ]; then
            echo "Error: yoso-gradedgather requires 2 arguments"
            usage
        fi
        N=$1
        K=$2
        echo "Running yoso gradedgather"
        cd ./dumbo-mpc/AsyRanTriGen
        # # 2) launch dynamic transfer protocol (re‑use run_beaver_triple)
        ./scripts/local_test.sh scripts/run_gradedgather.py "${N}" "${K}"
        ;;
    
    *)
        usage
        ;;
esac
