#!/bin/bash

help_usage() {
    echo "./syscallTrace_run.sh [security runtime]"
    echo "./syscallTrace_run.sh runsc"
}

if [ $# -lt 1 ]; then
    help_usage
    exit
fi

RUNTIME=$1

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
mkdir -p /opt/volume/runc_container/

#get system call list in container
echo "save syscall list"
sudo docker run -i -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} ./syscall_list.sh

        #container_id=$(docker ps | grep ${program} | cut -d" " -f1)
        #pgrep container -a | grep ${container_id} | awk '{print $1}'
sudo docker stop ${program}
sudo docker rm ${program}

#start runc runtime test container
sudo docker run -d -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program}

#get container pid information
container_id=$(docker ps | grep ${program} | cut -d" " -f1)
ltp_pid=$(pgrep container -a | grep ${container_id} | awk '{print $1}')
echo ${container_id}
echo ${ltp_pid}

#ftrace setting1
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 5s
sudo echo 1080800 > /sys/kernel/debug/tracing/buffer_size_kb
sudo echo function > /sys/kernel/debug/tracing/current_tracer
sudo echo ${ltp_pid} > /sys/kernel/debug/tracing/set_ftrace_pid
sudo echo function-fork > /sys/kernel/debug/tracing/trace_options
sudo echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable
sudo echo sys_exit* > /sys/kernel/debug/tracing/set_ftrace_filter

#ftrace on
sudo echo 1> /sys/kernel/debug/tracing/tracing_on

#start test program
sudo docker exec -it ${program} bash -c "./test_script.sh"

#ftrace off
sudo echo 0> /sys/kernel/debug/tracing/tracing_on

cp /sys/kernel/debug/tracing/trace /opt/volume/runc_container/ftrace.txt
sudo docker stop ${program}
sudo docker rm ${program}


mkdir -p /opt/volume/security_container

#start security runtime test container
sudo docker run --runtime=${RUNTIME} -d -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} 
#Get container information
container_id=$(docker ps | grep ${program} | cut -d" " -f1)
ltp_pid=$(pgrep container -a | grep ${container_id} | awk '{print $1}')
echo ${container_id}
echo ${ltp_pid}


#ftrace setting
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 5s
sudo echo 1080800 > /sys/kernel/debug/tracing/buffer_size_kb
sudo echo function > /sys/kernel/debug/tracing/current_tracer
sudo echo ${ltp_pid} > /sys/kernel/debug/tracing/set_ftrace_pid
sudo echo function-fork > /sys/kernel/debug/tracing/trace_options
sudo echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable
sudo echo sys_exit* > /sys/kernel/debug/tracing/set_ftrace_filter

#ftrace on
sudo echo 1> /sys/kernel/debug/tracing/tracing_on

#start test program
sudo docker exec -it ${program} bash -c "./test_script.sh"

#ftrace off
sudo echo 0> /sys/kernel/debug/tracing/tracing_on

cp /sys/kernel/debug/tracing/trace /opt/volume/security_container/ftrace.txt
docker stop ${program}
docker rm ${program}


#echo "tracing data processing ..."
#sudo docker run -i -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program} python3 avail_syscall.py
#docker stop ${program}
#docker rm ${program}
