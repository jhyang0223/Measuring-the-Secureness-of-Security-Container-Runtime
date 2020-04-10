#/bin/bash



sleep 2s

for syscall in $(ls testcases/kernel/syscalls/)
do
    for program in  $(ls -l testcases/kernel/syscalls/${syscall}/ | grep rwx | cut -d" " -f 9)
    do
        echo testcases/kernel/syscalls/${syscall}/${program}
        if [[ ${program} == "inotify09" ]] || [[ ${program} == "creat05" ]] ; then
            echo no execute ${program}
        else
            testcases/kernel/syscalls/${syscall}/${program}
        fi
    done
done
