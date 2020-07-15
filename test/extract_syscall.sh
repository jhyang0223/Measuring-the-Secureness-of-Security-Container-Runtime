#!/bin/bash
program=systrace
VOLUME_DIR=/opt/volume

#build and start container
echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . ) #>> /dev/null)

echo "tracing data processing ..."
sudo docker run -i -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} python3 avail_syscall.py
docker stop ${program}
docker rm ${program}
