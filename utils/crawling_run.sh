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

echo "Building container image for" ${program}
cd ../apps/${program} && sudo docker build -t ${program}:latest . 

if [[ $(docker ps -a | grep ${program} | awk '{print $2}') = "${program}" ]]; then
    sudo docker stop ${program}
    sudo docker rm ${program}
fi

mkdir -p ${HOST_VOLUME_DIR}

sudo docker run -i -t --rm -h ${program}  -v ${HOST_VOLUME_DIR}:${CONTAINER_VOLUME_DIR} --name ${program} ${program}
