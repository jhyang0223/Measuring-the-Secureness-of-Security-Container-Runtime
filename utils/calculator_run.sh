#!/bin/bash

program=calculator

help_usage() {
    echo "./calculator_run.sh"
    echo "./calculator_run.sh"
}

if [ $# -lt 0 ]; then
    help_usage
    exit
fi

###variable zone ###


HOST_VOLUME_DIR="/opt/volume"
CONTAINER_VOLUME_DIR="/opt/volume"
############

echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . ) #>> /dev/null)

if [[ $(docker ps -a | grep ${program} | awk '{print $2}') = "${program}" ]]; then
    sudo docker stop ${program}
    sudo docker rm ${program}
fi

mkdir -p ${HOST_VOLUME_DIR}

sudo docker run -i -t -h ${program} --rm -v ${HOST_VOLUME_DIR}:${CONTAINER_VOLUME_DIR} --name ${program} ${program}
