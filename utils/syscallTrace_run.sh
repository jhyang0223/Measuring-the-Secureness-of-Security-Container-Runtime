#!/bin/bash

help_usage() {
    echo "./syscallTrace_run.sh [security runtime] [cache mode]"
    echo "./syscallTrace_run.sh runsc cache"
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


mkdir -p /opt/volume/security_container

ltp_pid=$(pstree -ap | grep containerd | grep -v 'containerd-shim'| cut -d',' -f 2 | awk '{print $1}') #$(pgrep container -a | grep ${container_id} | awk '{print $1}')
echo ${ltp_pid}

#ftrace setting
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 1s
sudo echo > /sys/kernel/debug/tracing/trace
sleep 1s
sudo echo 1080800 > /sys/kernel/debug/tracing/buffer_size_kb
sleep 1s
sudo echo function > /sys/kernel/debug/tracing/current_tracer
sleep 1s
sudo echo ${ltp_pid}  > /sys/kernel/debug/tracing/set_ftrace_pid
sleep 1s
sudo echo ${ltp_pid}  > /sys/kernel/debug/tracing/set_event_pid
sleep 1s
sudo echo event-fork > /sys/kernel/debug/tracing/trace_options
sleep 1s
sudo echo function-fork > /sys/kernel/debug/tracing/trace_options
sleep 1s
sudo echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable
sleep 1s
sudo echo sys_ni_syscall > /sys/kernel/debug/tracing/set_ftrace_filter
sleep 1s
sudo echo 1 > /sys/kernel/debug/tracing/events/sched/sched_process_fork/enable
sleep 1s
sudo echo 1 > /sys/kernel/debug/tracing/events/sched/sched_process_exec/enable
sleep 1s

#ftrace on
sudo echo 1 > /sys/kernel/debug/tracing/tracing_on
sleep 1s


cat /sys/kernel/debug/tracing/trace_pipe > /opt/volume/security_container/ftrace.txt &
#start security runtime test container
sudo docker run --runtime=${RUNTIME} -d -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program}
#Get container information



#start test program
sudo docker exec -it ${program} bash -c "./test_script.sh"

#ftrace off
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 1s

#cp /sys/kernel/debug/tracing/trace /opt/volume/security_container/ftrace.txt
#echo ${ltp_pid} >> /opt/volume/security_container/ftrace.txt
docker stop ${program}
docker rm ${program}

if [ $# -lt 2 ]; then
    exit
fi



#start runc runtime test container
sudo docker run -d -t -h ${program} -v ${VOLUME_DIR}:${VOLUME_DIR} --cap-add SYS_PTRACE --name ${program} ${program}

container_id=$(docker ps | grep ${program} | cut -d" " -f1)
ltp_pid=$(pgrep container -a | grep ${container_id} | awk '{print $1}')
echo ${container_id}
echo ${ltp_pid}

#ftrace setting1
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 1s
sudo echo > /sys/kernel/debug/tracing/trace
sleep 1s
sudo echo 1080800 > /sys/kernel/debug/tracing/buffer_size_kb
sleep 1s
sudo echo function > /sys/kernel/debug/tracing/current_tracer
sleep 1s
sudo echo  > /sys/kernel/debug/tracing/set_ftrace_pid
sleep 1s
sudo echo  > /sys/kernel/debug/tracing/set_event_pid
sleep 1s
sudo echo event-fork > /sys/kernel/debug/tracing/trace_options
sleep 1s
sudo echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable
sleep 1s
sudo echo sys_ni_syscall > /sys/kernel/debug/tracing/set_ftrace_filter
sleep 1s

#ftrace on
sudo echo 1 > /sys/kernel/debug/tracing/tracing_on
sleep 1s
#start test program
sudo docker exec -it ${program} bash -c "./test_script.sh"

#ftrace off
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 1s

cat /sys/kernel/debug/tracing/set_ftrace_pid >> /opt/volume/runc_container/ftrace.txt

cp /sys/kernel/debug/tracing/trace /opt/volume/runc_container/ftrace.txt
test_pid=$(ps -el | grep 'test_script' | awk '{print $4}')
echo ${test_pid} >> /opt/volume/runc_container/ftrace.txt
sudo docker stop ${program}
sudo docker rm ${program}
