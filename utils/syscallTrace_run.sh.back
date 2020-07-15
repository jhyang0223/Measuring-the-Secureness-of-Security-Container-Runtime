#!/bin/bash

program=syscall_trace

if [[ $(docker ps -a | grep ${program} | awk '{print $2}') = "${program}" ]]; then
    sudo docker stop ${program}
    sudo docker rm ${program}
fi
VOLUME_DIR=/opt/volume

rm /opt/volume/syscall_list.txt
rm /opt/volume/security_container/*
rm /opt/volume/runc_container/*
#build and start container
echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . ) #>> /dev/null)
mkdir -p /opt/volume/security_container/

echo "save syscall list"
sudo docker run -i -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} ./syscall_list.sh

        #container_id=$(docker ps | grep ${program} | cut -d" " -f1)
        #pgrep container -a | grep ${container_id} | awk '{print $1}'
docker stop ${program}
docker rm ${program}

for syscall in $(cat /opt/volume/syscall_list.txt)
do
    sudo docker run -i -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} ./syscall_test_script_in_container.sh ${syscall}
    docker stop ${program}
    docker rm ${program}
done

sudo docker stop ${program}
sudo docker rm ${program}
#second we test host side strace
mkdir -p /opt/volume/runc_container
for syscall in $(cat /opt/volume/syscall_list.txt)
do
    if [[ ${syscall} == 'abort' ]];then
        echo no strace ${syscall}
    else
        sudo docker run --runtime=runsc -d -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} 
        #Get container information
        container_id=$(docker ps | grep ${program} | cut -d" " -f1)
        ltp_pid=$(ps -elf | grep runsc-sandbox | awk '{print $4}' | head -1) # ltp container pid (containerd-shim)
        echo ${container_id}
        echo ${ltp_pid}

        strace -f -ff -p ${ltp_pid} -e ${syscall} -o /opt/volume/host/syscall_trace_${syscall}.txt &
        docker exec -it ${program} bash -c "./syscall_test_script_in_host.sh ${syscall}"

        docker stop ${program}
        docker rm ${program}
    fi
done

#echo "tracing data processing ..."
#sudo docker run -i -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} python3 avail_syscall.py
#docker stop ${program}
#docker rm ${program}
