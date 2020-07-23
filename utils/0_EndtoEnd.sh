#!/bin/bash

help_usage() {
    echo "./0_EndtoEnd.sh [security runtime]"
    echo "./0_EndtoEnd.sh runsc"
}

if [ $# -lt 1 ]; then
    help_usage
    exit
fi



RUNTIME=$1

./crawlCode_run.sh
./riskGenerator_run.sh
./syscallTrace_run.sh ${RUNTIME}
./syscallAvail_run.sh
./calculator_run.sh
