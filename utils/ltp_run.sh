#!/bin/bash

program=ltp_test

help_usage() {
    echo "./ltp_run.sh [I/O Type]"
    echo "./ltp_run.sh fs"
    echo "[I/O Type] : fs, net"
}

if [ $# -lt 1 ]; then
    help_usage
    exit
fi

###parameter variable zone ###
IOTYPE=$1


############

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
sudo docker exec -dt ${program} bash -c "./test_script.sh ${IOTYPE}"

#ftrace setting
sudo echo 1080800 > /sys/kernel/debug/tracing/buffer_size_kb
sudo echo function > /sys/kernel/debug/tracing/current_tracer
sudo echo $(ps -el | grep ${ltp_pid} | awk '{print $4}') > /sys/kernel/debug/tracing/set_ftrace_pid
sudo echo function-fork > /sys/kernel/debug/tracing/trace_options

#strace setting
test_script_pid=$(ps -el | grep ${ltp_pid} | grep wait | awk '{print $4}')
echo ${test_script_pid}
#ftrace start
sudo echo 1 > /sys/kernel/debug/tracing/tracing_on
#strace start
strace -f -p ${test_script_pid} -o /opt/volume/${IOTYPE}_strace.txt

#wait bench tool exit
#echo "wait test program exit"
#while [[ $(ps -el | grep ${ltp_pid} | grep wait | awk '{print $4}') != "" ]]
#do
#    echo -n "."
#    sleep 10
#done
#echo ""

#ftrace off
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
echo "ftrace off"
#save trace file
cp /sys/kernel/debug/tracing/trace /opt/volume/${IOTYPE}_ftrace.txt
