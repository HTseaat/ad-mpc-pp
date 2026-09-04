#!/bin/bash

# Ensure NUM_NODES argument is passed
if [ $# -lt 1 ]; then
    echo "Usage: $0 <NUM_NODES>"
    exit 1
fi

NUM_NODES=$1
FINISHED_PATTERN=${2:-"${FINISHED_PATTERN:-Finished}"}
FINAL_LAYER_START=${FINAL_LAYER_START:-}
FINAL_LAYER_PATTERN=${FINAL_LAYER_PATTERN:-}
FINAL_LAYER_THRESHOLD=${FINAL_LAYER_THRESHOLD:-}
REQUIRED_NODE_IDS=${REQUIRED_NODE_IDS:-}
REQUIRED_NODE_PATTERN=${REQUIRED_NODE_PATTERN:-}
LOG_DIR="../AsyRanTriGen/log"  # Adjust the path to your logs directory if needed

if { [ -n "$FINAL_LAYER_START" ] && [ -z "$FINAL_LAYER_PATTERN" ]; } || \
   { [ -z "$FINAL_LAYER_START" ] && [ -n "$FINAL_LAYER_PATTERN" ]; }; then
    echo "FINAL_LAYER_START and FINAL_LAYER_PATTERN must be set together."
    exit 1
fi

if [ -n "$FINAL_LAYER_START" ] && ! [[ "$FINAL_LAYER_START" =~ ^[0-9]+$ ]]; then
    echo "FINAL_LAYER_START must be a non-negative integer."
    exit 1
fi

if [ -n "$FINAL_LAYER_THRESHOLD" ]; then
    if [ -z "$FINAL_LAYER_START" ] || [ -z "$FINAL_LAYER_PATTERN" ]; then
        echo "FINAL_LAYER_THRESHOLD requires FINAL_LAYER_START and FINAL_LAYER_PATTERN."
        exit 1
    fi
    if ! [[ "$FINAL_LAYER_THRESHOLD" =~ ^[0-9]+$ ]] || [ "$FINAL_LAYER_THRESHOLD" -le 0 ]; then
        echo "FINAL_LAYER_THRESHOLD must be a positive integer."
        exit 1
    fi
    FINAL_LAYER_SIZE=$((NUM_NODES - FINAL_LAYER_START))
    if [ "$FINAL_LAYER_SIZE" -le 0 ] || [ "$FINAL_LAYER_THRESHOLD" -gt "$FINAL_LAYER_SIZE" ]; then
        echo "FINAL_LAYER_THRESHOLD exceeds the final-layer size."
        exit 1
    fi
fi

if { [ -n "$REQUIRED_NODE_IDS" ] && [ -z "$REQUIRED_NODE_PATTERN" ]; } || \
   { [ -z "$REQUIRED_NODE_IDS" ] && [ -n "$REQUIRED_NODE_PATTERN" ]; }; then
    echo "REQUIRED_NODE_IDS and REQUIRED_NODE_PATTERN must be set together."
    exit 1
fi

NORMALIZED_REQUIRED_NODE_IDS=${REQUIRED_NODE_IDS//,/ }
for REQUIRED_ID in $NORMALIZED_REQUIRED_NODE_IDS; do
    if ! [[ "$REQUIRED_ID" =~ ^[0-9]+$ ]]; then
        echo "REQUIRED_NODE_IDS must contain only non-negative integers."
        exit 1
    fi
done

# Check if the log directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "Log directory $LOG_DIR does not exist."
    exit 1
fi

# Array to store the status of each log file
declare -A log_status

# Initialize log status for all logs
for ID in $(seq 0 $((NUM_NODES - 1))); do
    log_status[$ID]=false
done

# Monitor logs until the finished marker is found in all log files.

# Loop to check logs
while true; do
    if [ -n "$FINAL_LAYER_THRESHOLD" ]; then
        final_finished=0
        for ID in $(seq "$FINAL_LAYER_START" $((NUM_NODES - 1))); do
            LOG_FILE="$LOG_DIR/logs-${ID}.log"
            if grep -q -E "$FINAL_LAYER_PATTERN" "$LOG_FILE"; then
                final_finished=$((final_finished + 1))
            fi
        done
        if [ "$final_finished" -ge "$FINAL_LAYER_THRESHOLD" ]; then
            break
        fi
        sleep 1
        continue
    fi

    all_finished=true
    # Check each log file for 'Finished' keyword
    for ID in $(seq 0 $((NUM_NODES - 1))); do
        LOG_FILE="$LOG_DIR/logs-${ID}.log"
        NODE_PATTERN="$FINISHED_PATTERN"
        if [ -n "$FINAL_LAYER_START" ] && [ "$ID" -ge "$FINAL_LAYER_START" ]; then
            NODE_PATTERN="$FINAL_LAYER_PATTERN"
        fi
        for REQUIRED_ID in $NORMALIZED_REQUIRED_NODE_IDS; do
            if [ "$ID" -eq "$REQUIRED_ID" ]; then
                NODE_PATTERN="$REQUIRED_NODE_PATTERN"
                break
            fi
        done
        
        # Check if the finished marker appears in the log file
        if grep -q -E "$NODE_PATTERN" "$LOG_FILE"; then
            # echo "'Finished' found in $LOG_FILE"
            log_status[$ID]=true
        fi
        
        # If any log file does not have 'Finished', set all_finished to false
        if [ "${log_status[$ID]}" = false ]; then
            all_finished=false
        fi
    done
    
    # If all logs contain 'Finished', exit the loop
    if [ "$all_finished" = true ]; then
        break
    fi
    
    # Sleep before checking again
    sleep 1
done

# echo "'Finished' detected in all log files. Exiting script."
exit 0  # Explicitly exit with a success code
