#!/bin/bash

program=syscall_trace
VOLUME_DIR=/opt/volume
if [[ $(docker ps -a | grep ${program} | awk '{print $2}') = "${program}" ]]; then
    sudo docker stop ${program}
    sudo docker rm ${program}
fi


echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . ) #>> /dev/null)

echo "tracing data processing ..."
sudo docker run -i -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} python3 avail_syscall.py
docker stop ${program}
docker rm ${program}
