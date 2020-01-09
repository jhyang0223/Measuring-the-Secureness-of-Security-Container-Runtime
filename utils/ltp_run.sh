#!/bin/bash

program=ltp_test

help_usage() {
    echo "./ltp_run.sh"
    echo "./ltp_run.sh"
}

if [ $# -lt 0 ]; then
    help_usage
    exit
fi

###parameter variable zone ###



############

echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . )#>> /dev/null)

sudo docker run -i -t -h ${program} --name ${program} ${program} /bin/bash
