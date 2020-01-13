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

if [[ $(docker ps | grep ${program} | cut -d" " -f9) = "${program}" ]]; then
    sudo docker stop ${program}
    sudo docker rm ${program}
fi

echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . ) #>> /dev/null)

sudo docker run -i -t -h ${program} --name ${program} ${program}

container_id=$(docker ps | grep ${program} | cut -d" " -f1)
ltp_pid=$(pgrep container -a | grep ${container_id} | awk '{print $1}')


