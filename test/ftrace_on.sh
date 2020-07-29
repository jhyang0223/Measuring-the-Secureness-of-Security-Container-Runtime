#!/bin/bash


pid=$1

#ftrace setting1
sudo echo 0 > /sys/kernel/debug/tracing/tracing_on
sleep 1s
sudo echo 1080800 > /sys/kernel/debug/tracing/buffer_size_kb
sudo echo function > /sys/kernel/debug/tracing/current_tracer
sudo echo ${pid} > /sys/kernel/debug/tracing/set_ftrace_pid
sudo echo function-fork > /sys/kernel/debug/tracing/trace_options
sudo echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable
sudo echo sys_exit* > /sys/kernel/debug/tracing/set_ftrace_filter

#ftrace on
sudo echo 1> /sys/kernel/debug/tracing/tracing_on

#start test program
#sudo docker exec -it ${program} bash -c "./test_script.sh"
sleep 10s
cat /sys/kernel/debug/tracing/set_ftrace_pid
sleep 10s
cat /sys/kernel/debug/tracing/set_ftrace_pid
#ftrace off
sudo echo 0> /sys/kernel/debug/tracing/tracing_on
