#!/bin/bash

#for syscall in $(cat /opt/volume/syscall_list.txt)
#do
#    for program in  $(ls -l testcases/kernel/syscalls/${syscall}/ | grep rwx | cut -d" " -f 9)
#        do
#            sleep 5s
#            echo testcases/kernel/syscalls/${syscall}/${program}
#            if [[ ${program} == "inotify09" ]] || [[ ${program} == "creat05" ]] || [[ ${program} == "keyctl01" ]] || [[ ${program} == "epoll_wait03" ]] || [[ ${program} == "fork12" ]] || [[ ${program} == "fork09" ]] || [[ ${program} == "kill10" ]] || [[ ${program} == "open03" ]] || [[ ${program} == "mkdir09" ]] || [[ ${program} == "futex_cmp_requeue01" ]] || [[ ${program} == "pipe09" ]] ; then
#               echo no execute ${program}
#           else
#               timeout -s 9 300s testcases/kernel/syscalls/${syscall}/${program}
#           fi
#    done
#done

#timeout -s 9 300s testcases/kernel/syscalls/socket/socket02


syscall=$1
for program in $(ls -l testcases/kernel/syscalls/${syscall}/ | grep rwx | awk '{print $9}')
    do
        echo testcases/kernel/syscalls/${syscall}/${program}
        if [[ ${program} == "inotify09" ]] || [[ ${program} == "creat05" ]] || [[ ${program} == "keyctl01" ]] || [[ ${program} == "epoll_wait03" ]] || [[ ${program} == "fork12" ]] || [[ ${program} == "fork09" ]] || [[ ${program} == "kill10" ]] || [[ ${program} == "open03" ]] || [[ ${program} == "mkdir09" ]] || [[ ${program} == "futex_cmp_requeue01" ]] || [[ ${program} == "pipe09" ]] ; then
            echo no execute ${program}
        else
            timeout -s 9 300s testcases/kernel/syscalls/${syscall}/${program}
        fi
    done

ipcArray= ("msgctl" "msgget" "msgrcv" "msgsnd" "msgstress" "semctl" "semget" "semop" "shmat" "shmctl" "shmdt" "shmget")

for ipcSyscall in "${ipcArray[@]}"; do
    for program in  $(ls -l testcases/kernel/syscalls/ipc/${ipcSyscall}/ | grep rwx | awk '{print $9}')
        do
            sleep 5s
            echo /opt/ltp/testcases/kernel/syscalls/ipc/${ipcSyscall}/${program}
            timeout -s 9 300s testcases/kernel/syscalls/ipc/${ipcSyscall}/${program}
    done
done
