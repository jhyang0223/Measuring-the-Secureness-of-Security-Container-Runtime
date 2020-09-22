#!/bin/bash

ipcArray=("msgctl" "msgget" "msgrcv" "msgsnd" "msgstress" "semctl" "semget" "semop" "shmat" "shmctl" "shmdt" "shmget")

for ipcSyscall in "${ipcArray[@]}"; do
    for program in  $(ls -l testcases/kernel/syscalls/ipc/${ipcSyscall}/ | grep rwx | awk '{print $9}')
        do
            if [[ ${program} == "msgstress04" ]] ; then
                echo no execute ${program}
            else
                sleep 5s
                echo /opt/ltp/testcases/kernel/syscalls/ipc/${ipcSyscall}/${program}
                timeout -s 9 300s testcases/kernel/syscalls/ipc/${ipcSyscall}/${program}
            fi
    done
done
