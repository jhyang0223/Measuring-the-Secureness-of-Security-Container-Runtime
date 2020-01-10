#!/bin/bash

program=crawling

help_usage() {
    echo "./crawling_run.sh"
    echo "./crawling_run.sh"
}

if [ $# -lt 0 ]; then
    help_usage
    exit
fi

###parameter variable zone ###


HOST_VOLUME_DIR="/opt/volume"
CONTAINER_VOLUME_DIR="/opt/volume"
############

echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . )#>> /dev/null)

if [[ $(docker ps | grep ${program}) = "${program}" ]]; then
    sudo docker stop ${program}
    sudo docker rm ${program}
fi

mkdir -p ${HOST_VOLUME_DIR}

sudo docker run -i -t -h ${program} --rm -v ${HOST_VOLUME_DIR}:${CONTAINER_VOLUME_DIR} --name ${program} ${program}
