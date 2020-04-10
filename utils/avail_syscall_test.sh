#!/bin/bash

program=ltp_test



if [[ $(docker ps -a | grep ${program} | awk '{print $2}') = "${program}" ]]; then
    sudo docker stop ${program}
    sudo docker rm ${program}
fi

#build and start container
echo "Building container image for" ${program} #>> /dev/null
(cd ../apps/${program} && sudo docker build -t ${program}:latest . ) #>> /dev/null)
sudo docker run -d -t -h ${program} --name ${program} ${program}

#Get container information
container_id=$(docker ps | grep ${program} | cut -d" " -f1)
ltp_pid=$(pgrep container -a | grep ${container_id} | awk '{print $1}') # ltp container pid (containerd-shim)

#Execute Test Program
#sudo docker exec -dt ${program} bash -c "./syscall_test_script.sh"

#strace setting
#test_script_pid=$(ps -el | grep ${ltp_pid} | grep wait | awk '{print $4}')
#echo ${test_script_pid}
#strace start
#strace -ff -xx -ttt -p ${test_script_pid} -o /opt/volume/syscall_strace.txt
