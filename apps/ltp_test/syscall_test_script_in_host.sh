#!/bin/bash


syscall=$1
for program in  $(ls -l testcases/kernel/syscalls/${syscall}/ | grep rwx | cut -d" " -f 9)
    do
        sleep 5s
        echo testcases/kernel/syscalls/${syscall}/${program}
        if [[ ${program} == "inotify09" ]] || [[ ${program} == "creat05" ]] || [[ ${program} == "keyctl01" ]] || [[ ${program} == "epoll_wait03" ]] || [[ ${program} == "fork12" ]] || [[ ${program} == "fork09" ]] || [[ ${program} == "kill10" ]] || [[ ${program} == "open03" ]] || [[ ${program} == "mkdir09" ]] || [[ ${program} == "futex_cmp_requeue01" ]] || [[ ${program} == "pipe09" ]] ; then
            echo no execute ${program}
        else
            timeout -s 9 300s testcases/kernel/syscalls/${syscall}/${program}
        fi
    done