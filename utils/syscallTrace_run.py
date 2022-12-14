#!/usr/bin/env python3
import os
import sys
import subprocess
import io
import glob
import time
import threading
import pickle
import signal

#for saving dictionary to disk
def SaveDict(myDict,path):
    with open(path,"wb") as f:
        pickle.dump(myDict, f)

#trace pipe for host side trace
def TraceDataSaveD(fileName):
    cmd = 'cat /sys/kernel/debug/tracing/trace_pipe > /opt/volume/host/'+ fileName
    os.system(cmd)

#get system call list in ltp test syscall test programs
def GetSyscallList(image,volume_opt, mode):
    print('save syscall list')

    if mode == "full":
        cmd = 'sudo docker run -i -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image+ ' ./syscall_list.sh'
        os.system(cmd)

        os.system('sudo docker stop '+ image)
        os.system('sudo docker rm '+ image)

    elif mode == "simple":
        cmd = "cp syscall_list.txt /opt/volume/syscall_list.txt"
        os.system(cmd)
    
#to ftrace setting for container tracing
def FtraceSetting(trace_pid_string, baseSystem):
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

    if baseSystem == "container":
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

#    cmd = 'sudo echo 1 > /sys/kernel/debug/tracing/events/syscalls/enable'
#    os.system(cmd)
#    time.sleep(1)

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


#save trace data in disk from trace buffer
def SaveTrace(saveFileName):
    time.sleep(2)

    cmd = 'cat /sys/kernel/debug/tracing/trace > /opt/volume/security_container/' + saveFileName
    os.system(cmd)

    cmd = 'sudo echo 0 > /sys/kernel/debug/tracing/tracing_on'
    os.system(cmd)
    time.sleep(1)

#get pid from ps command
def GetPidString(cmd):
    pid_list = subprocess.check_output(cmd,shell=True).decode().strip("\n").split('\n')
    pid_string = ''
    for pid in pid_list:
        pid_string += pid +' '
    print(pid_string)
    return pid_string

#get pid to have parent in ppid list
def GetPidFromPpid(ppid_list):
    cmd = 'ps -eTf | grep '
    for ppid in ppid_list:
        cmd += " -e "+ppid
    cmd += " | awk '{print $3}'"

    return GetPidString(cmd)

def GetProcInfoDict(tgidList,procInfoDict):
    for tgid in tgidList:
        if os.path.exists('/proc/'+tgid):
            procPathCat = 'cat /proc/'+tgid+'/cmdline'   
            procInfo  = subprocess.check_output(procPathCat, shell=True).decode().strip("\n")[0:20]
            if procInfoDict.get(procInfo) == None:
                procInfoDict[procInfo] = list()
            procInfoDict[procInfo].append(tgid)

def SigHandler(signum, frame):
    pass

if __name__ == "__main__":
    if len(sys.argv) is not 3:
        print("syscallTrace_run.py [runtime] [mode]")
        print("mode - full : tracing about all system call test program")
        print("mode - simple : tracing about one system call test program")
        print("example : python3 syscallTrace_run.py runsc full")
        exit(1)

    image = 'syscall_trace'
    volume_opt = '/opt/volume:/opt/volume'
    runtime = sys.argv[1]
    mode = sys.argv[2]
    
    firstDir = os.getcwd()    

    cmd = "docker ps -a | grep "+image + " | awk '{print $2}'"
    if subprocess.check_output(cmd,shell=True).decode().strip("\n") == image:
        os.system('sudo docker stop '+ image)
        os.system('sudo docker rm '+ image)

    os.system("mkdir -p /opt/volume/host")
    os.system("mkdir -p /opt/volume/program")
    os.system("mkdir -p /opt/volume/ps")
  
    os.system('rm /opt/volume/syscall_list.txt')
    os.system('rm /opt/volume/security_container/*')
    os.system('rm /opt/volume/program/*')
    os.system('rm /opt/volume/ps/*')
    
    print('Building container image for ' + image)
    
    cmd = 'cd ../apps/'+image+' && sudo docker build -t '+image+':latest .'
    os.system(cmd)

    GetSyscallList(image,volume_opt,mode)

    # get containerd proces pid for tracing container work including start up and exit
    cmd = "pstree -ap | grep containerd | grep -v 'containerd-shim'| cut -d',' -f 2 | awk '{print $1}'"
    containerd_pid_string = GetPidString(cmd)

    FtraceSetting(containerd_pid_string,"container")

    #start up and end time system call tracing
#    cmd = 'sudo docker run -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image    
    cmd = 'sudo docker run --runtime='+runtime+' -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
    os.system(cmd)

    cmd = 'ps -eL -o pid,tgid,ppid,cmd > /opt/volume/ps/StartExit.txt'
    os.system(cmd)    

    os.system('sudo docker stop '+ image)
    os.system('sudo docker rm '+ image)

    SaveTrace('StartExit.txt')
    syscall_list = list()
    
    ##tracing each system call test
    ##traced procedure is in "" "" : contaienr start up --> ""execute one system call test program"" --> container exit
    ##I select this for loop method, because ftrace provide just buffer content
    procInfoDict = dict()
    
    with open('/opt/volume/syscall_list.txt',"r") as syscallListFile:
        for syscallLine in syscallListFile:
            syscall = syscallLine.strip("\n")
            print(syscall)
            #runtime tracing
            if runtime == "runc":
                cmd = 'sudo docker run -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
            else:
                cmd = 'sudo docker run --runtime='+runtime+' -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
            os.system(cmd)

            cmd = 'ps -eL -o pid,tgid,ppid,cmd > /opt/volume/ps/' + syscall + '.txt'
            os.system(cmd)

            if runtime == "runc":
                cmd = "pstree -ap | grep 'containerd-shim' | cut -d',' -f 2 | awk '{print $1}'"
            elif runtime == "runsc":
                cmd = "ps -ef | grep 'containerd-shim' |  awk '{print $2}'"
            elif runtime == "kata-runtime":
                cmd = "ps -ef | grep 'containerd-shim' | awk '{print $2}'"
            target_ppid_string = GetPidString(cmd) # tgid
            target_ppid_list = target_ppid_string.strip(" ").split(" ") #tgid list
            target_pid_string = GetPidFromPpid(target_ppid_list)
            
            GetProcInfoDict(target_ppid_list, procInfoDict)

            FtraceSetting(target_pid_string,"container")  

#            if runtime != "runc":

#                cmd = 'sudo echo noevent-fork > /sys/kernel/debug/tracing/trace_options'
#                os.system(cmd)
#                time.sleep(1)

#                cmd = 'sudo echo nofunction-fork > /sys/kernel/debug/tracing/trace_options'
#                os.system(cmd)
#                time.sleep(1)

            startTime = time.time()

            #Test Program Start
            cmd = 'sudo docker exec -it '+image+' bash -c "./test_script.sh ' + syscall  + ' "'
            os.system(cmd)
            endTime = time.time()
            time.sleep(2) 
            SaveTrace(syscall+'.txt')
            os.system('sudo docker stop '+ image)
            os.system('sudo docker rm '+ image)
            syscall_list.append(syscall)
    
            
    if mode == "full":
        if runtime == "runc":
            cmd = 'sudo docker run -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
        else:
            cmd = 'sudo docker run --runtime='+runtime+' -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
        os.system(cmd)

        cmd = 'ps -eL -o pid,tgid,ppid,cmd > /opt/volume/ps/ipc.txt'
        os.system(cmd)


        if runtime == "runc":
            cmd = "pstree -ap | grep 'containerd-shim' | cut -d',' -f 2 | awk '{print $1}'"
        elif runtime == "runsc":
            cmd = "ps -ef | grep 'containerd-shim' |  awk '{print $2}'"
        elif runtime == "kata-runtime":
            cmd = "ps -ef | grep 'containerd-shim' | awk '{print $2}'"
        target_ppid_string = GetPidString(cmd) # tgid
        target_ppid_list = target_ppid_string.strip(" ").split(" ") #tgid list
        target_pid_string = GetPidFromPpid(target_ppid_list)

        GetProcInfoDict(target_ppid_list, procInfoDict)

        FtraceSetting(target_pid_string,"container")

#            if runtime != "runc":

#                cmd = 'sudo echo noevent-fork > /sys/kernel/debug/tracing/trace_options'
#                os.system(cmd)
#                time.sleep(1)

#                cmd = 'sudo echo nofunction-fork > /sys/kernel/debug/tracing/trace_options'
#                os.system(cmd)
#                time.sleep(1)


        #Test Program Start
        cmd = 'sudo docker exec -it '+image+' bash -c "./test_ipc.sh"'
        os.system(cmd)
        time.sleep(2)
        SaveTrace('ipc.txt')
        os.system('sudo docker stop '+ image)
        os.system('sudo docker rm '+ image)
       # syscall_list.append(syscall)
    SaveDict(procInfoDict,"/opt/volume/security_container/procInfoDict.sav")    

    
#######################################################################################################################
#trace for program in container side test
    
    with open('/opt/volume/syscall_list.txt', 'r') as syscallListFile:
        for syscallLine in syscallListFile:
            syscall = syscallLine.strip("\n")
            print(syscall)
            if runtime == "runc":
                cmd = 'sudo docker run -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
            else:
                cmd = 'sudo docker run --runtime='+runtime+' -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
            os.system(cmd)

            cmd = 'sudo docker exec -it ' + image + ' bash -c "./test_script_strace.sh ' + syscall +' "'
            os.system(cmd)

            os.system('sudo docker stop ' + image)
            os.system('sudo docker rm ' + image)
    
    if mode == "full":
        #ipc systemcalls testing...
        if runtime == "runc":
            cmd = 'sudo docker run -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
        else:
            cmd = 'sudo docker run --runtime='+runtime+' -d -t -h '+image+' -v '+volume_opt+' --cap-add SYS_PTRACE --name '+ image +' ' + image
        os.system(cmd)

        cmd = 'sudo docker exec -it ' + image + ' bash -c "./test_ipc_strace.sh"'
        os.system(cmd)

######################################################################################################################
#trace for host side test
    ''' 
    #if this machine doesn't ltp test environment...
    if os.path.isdir("/opt/ltp") == False:
        os.system("git clone https://github.com/linux-test-project/ltp.git /opt/ltp")
        os.chdir("/opt/ltp")
        os.system("make autotools")
        os.system("./configure")
        os.system("make")
        os.system("make install")

    os.chdir(firstDir)
    #tracing to ltp program execution in host (not container...)
    if os.path.isdir("/opt/volume/host/ftrace_full.txt") == True and mode == "full":
        pass
    elif os.path.isdir("/opt/volume/host/ftrace_simple.txt") == True and mode == "simple":
        pass
    else:
        #rm all unused data in /opt/volume/host
        os.system("rm /opt/volume/host/*")
        #trace setting
        cmd = "ps -ef | grep 'syscallTrace' | awk '{print $2}'"
        target_pid_string = GetPidString(cmd)
        target_pid_list = target_pid_string.strip(" ").split(" ")

        ppid = os.getpid()
        pid = os.fork()

        if pid == 0: # child
            FtraceSetting(target_pid_string,"host")
            saveFileName = 'ftrace_' + mode + '.txt'
            cmd = 'sudo echo function-fork > /sys/kernel/debug/tracing/trace_options'
            os.system(cmd)
            time.sleep(1)

            cmd = 'sudo echo event-fork > /sys/kernel/debug/tracing/trace_options'
            os.system(cmd)
            time.sleep(1)
            os.kill(ppid, signal.SIGUSR1)
            TraceDataSaveD(saveFileName)
        else : # parent
            #execute test programs
            signal.signal(signal.SIGUSR1, SigHandler)
            signal.pause()
            print("end pause")
            os.system("./test_script_host.sh")
            if mode =="full":
                os.system("./test_ipc_host.sh")
            time.sleep(5)

            cmd = "kill -9 $(ps -ef | grep trace_pipe | awk '{print $2}')"
            os.system(cmd)
    
    '''        
    print("elapsedTime",str(endTime - startTime))
