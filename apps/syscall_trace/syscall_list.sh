#!/bin/bash

for syscall in $(ls -l testcases/kernel/syscalls/ | grep "^d" | awk '{print $9}')
do
    echo ${syscall} >> /opt/volume/syscall_list.txt
done
