#!/bin/bash

help_usage() {
    echo "./1_simple_e2e.sh [security runtime]"
    echo "./1_simple_e2e.sh runsc"
}

if [ $# -lt 1 ]; then
    help_usage
    exit
fi


RUNTIME=$1

./crawlCode_run.sh
./riskGenerator_run.sh
./simpleTrace_run.sh ${RUNTIME}
./syscallAvail_run.sh
./calculator_run.sh
