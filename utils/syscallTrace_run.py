import os
import sys
import subprocess
import io
import glob
import time
import threading

def TraceDataSaveD():
    cmd = 'cat /sys/kernel/debug/tracing/trace_pipe > /opt/volume/security_container/ftrace.txt'
    os.system(cmd)

def GetSyscallList(image,volume_opt):
    print('save syscall list')

    cmd = 'sudo docker run -i -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image+ ' ./syscall_list.sh'
    os.system(cmd)

    os.system('sudo docker stop '+ image)
    os.system('sudo docker rm '+ image)

def FtraceSetting(trace_pid_string):
    os.system('mkdir -p /opt/volume/security_container')
    os.system('trace-cmd reset')
    time.sleep(1)

    cmd = "kill -9 $(ps -ef | grep trace_pipe | awk '{print $2}')"
    os.system(cmd)

    os.system('sudo echo 0 > /sys/kernel/debug/tracing/tracing_on')
    time.sleep(1)

    os.system('sudo echo > /sys/kernel/debug/tracing/trace')
    time.sleep(1)

    os.system('sudo echo 1080800 > /sys/kernel/debug/tracing/buffer_size_kb')
    time.sleep(1)

    os.system('sudo echo function > /sys/kernel/debug/tracing/current_tracer')
    time.sleep(1)

    cmd = "sudo echo "+ trace_pid_string  +'  > /sys/kernel/debug/tracing/set_ftrace_pid'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo '+ trace_pid_string  +'  > /sys/kernel/debug/tracing/set_event_pid'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo event-fork > /sys/kernel/debug/tracing/trace_options'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo function-fork > /sys/kernel/debug/tracing/trace_options'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo record-tgid > /sys/kernel/debug/tracing/trace_options'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/enable'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo 1 > /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/enable'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo sys_ni_syscall > /sys/kernel/debug/tracing/set_ftrace_filter'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo 1 > /sys/kernel/debug/tracing/events/sched/sched_process_fork/enable'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo 1 > /sys/kernel/debug/tracing/events/sched/sched_process_exec/enable'
    os.system(cmd)
    time.sleep(1)

    cmd = 'sudo echo 1 > /sys/kernel/debug/tracing/tracing_on'
    os.system(cmd)
    time.sleep(1)


def SaveTrace(saveFileName):
    time.sleep(2)

    cmd = 'cat /sys/kernel/debug/tracing/trace > /opt/volume/security_container/' + saveFileName
    os.system(cmd)

    cmd = 'sudo echo 0 > /sys/kernel/debug/tracing/tracing_on'
    os.system(cmd)
    time.sleep(1)

def GetPidString(cmd):
    pid_list = subprocess.check_output(cmd,shell=True).decode().strip("\n").split('\n')
    pid_string = ''
    for pid in pid_list:
        pid_string += pid +' '
    print(pid_string)
    return pid_string

def GetPidFromPpid(ppid_list):
    cmd = 'ps -eTf | grep '
    for ppid in ppid_list:
        cmd += " -e "+ppid
    cmd += " | awk '{print $3}'"

    return GetPidString(cmd)

if __name__ == "__main__":
    if len(sys.argv) is not 2:
        print("syscallTrace_run.py [runtime]")
        print("example : python3 syscallTrace_run.py runsc")
        exit(1)

    image = 'syscall_trace'
    volume_opt = '/opt/volume:/opt/volume'
    runtime = sys.argv[1]
    
    cmd = "docker ps -a | grep "+image + " | awk '{print $2}'"
    if subprocess.check_output(cmd,shell=True).decode().strip("\n") == image:
        os.system('sudo docker stop '+ image)
        os.system('sudo docker rm '+ image)

    os.system('rm /opt/volume/syscall_list.txt')
    os.system('rm /opt/volume/security_container/*')
    os.system('rm /opt/volume/runc_container/*')
    
    print('Building container image for ' + image)
    
    cmd = 'cd ../apps/'+image+' && sudo docker build -t '+image+':latest .'
    os.system(cmd)

    GetSyscallList(image,volume_opt)
    
    cmd = "pstree -ap | grep containerd | grep -v 'containerd-shim'| cut -d',' -f 2 | awk '{print $1}'"
    containerd_pid_string = GetPidString(cmd)

    FtraceSetting(containerd_pid_string)

    #start up and end time system call tracing
#    cmd = 'sudo docker run -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image    
    cmd = 'sudo docker run --runtime '+runtime+' -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
    os.system(cmd)    
    os.system('sudo docker stop '+ image)
    os.system('sudo docker rm '+ image)

    SaveTrace('StartExit.txt')
  
    
    with open('/opt/volume/syscall_list.txt',"r") as syscallListFile:
        for syscallLine in syscallListFile:
            syscall = syscallLine.strip("\n")
            print(syscall)
            #runtime tracing
#            cmd = 'sudo docker run -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
            cmd = 'sudo docker run --runtime '+runtime+' -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
            os.system(cmd)

#            cmd = "pstree -ap | grep 'containerd-shim' | cut -d',' -f 2 | awk '{print $1}'"
            cmd = "ps -ef | grep -e 'runsc' |  awk '{print $2}'"
            target_ppid_string = GetPidString(cmd)
            target_ppid_list = target_ppid_string.strip(" ").split(" ")
            target_pid_string = GetPidFromPpid(target_ppid_list)
            
            FtraceSetting(target_pid_string)  

            cmd = 'sudo echo noevent-fork > /sys/kernel/debug/tracing/trace_options'
#            os.system(cmd)
            time.sleep(1)

            cmd = 'sudo echo nofunction-fork > /sys/kernel/debug/tracing/trace_options'
#            os.system(cmd)
            time.sleep(1)


            #Test Program Start
            cmd = 'sudo docker exec -it '+image+' bash -c "./test_script.sh ' + syscall  + ' "'
            os.system(cmd)
    
            SaveTrace(syscall+'.txt')
            os.system('sudo docker stop '+ image)
            os.system('sudo docker rm '+ image)
