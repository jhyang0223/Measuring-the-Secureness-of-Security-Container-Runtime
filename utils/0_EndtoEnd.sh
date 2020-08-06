#!/bin/bash

help_usage() {
    echo "./0_EndtoEnd.sh [security runtime] [mode]"
    echo "mode - full, simple"
    echo "./0_EndtoEnd.sh runsc full"
}

if [ $# -lt 2 ]; then
    help_usage
    exit
fi

RUNTIME=$1
MODE=$2

./crawlCode_run.sh
./riskGenerator_run.sh
./syscallTrace_run.sh ${RUNTIME} ${MODE}
./syscallAvail_run.sh
./calculator_run.sh
