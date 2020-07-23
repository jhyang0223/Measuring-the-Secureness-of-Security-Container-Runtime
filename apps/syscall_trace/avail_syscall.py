from typing import Any
import subprocess
import os
import io
import pickle
from typing import Any

import glob
import re

#Return available system call (in docker) and system call number pair
def GetLinuxSyscallDict():
    linux_syscallDict = dict()
    #system call string is usually '#define .* __NR_(system_call) .*'
    lFormat = re.compile('.*NR_([0-9a-zA-Z_]+) ([0-9]+)')

    #This command get string in library header file
    cmd = '''cat $(printf "#include <sys/syscall.h>\nSYS_read" | gcc -E - | awk '{print $3}' | grep -v -e '^$' | grep -v -e '<' | sed 's/\"//g') | grep "#define" | grep "NR_" | sort -u'''
    catResult = subprocess.check_output(cmd,shell=True).decode().strip("\n")
    catResultIO = io.StringIO(catResult)

    #examine each line fits to my regular expression
    for line in catResultIO.readlines():
        searchRet  = lFormat.search(line.strip("\n"))
        if searchRet is not None:
            linux_syscallDict[searchRet.group(2)] = searchRet.group(1)
    print(len(linux_syscallDict))
    return linux_syscallDict

def MakeSyscallCntDict(ftraceFilePath,linux_syscallDict):
    template = ".+ sys_exit: NR ([0-9]+) = ([0-9]+)"
    compiled = re.compile(template)
    syscallCntDict = dict()
    with open(ftraceFilePath) as ftraceFile:
        for ftraceLine in ftraceFile.readlines():
            retMatch = compiled.match(ftraceLine)
            if retMatch != None:
                syscallNum = retMatch.group(1)
                syscall = linux_syscallDict[syscallNum]
                if syscallCntDict.get(syscall) == None:
                    print(syscall)
                    syscallCntDict[syscall] =0
                syscallCntDict[syscall]+=1

    return syscallCntDict

def MakeAvailSyscallDict(scSyscallDict, runcSyscallDict):
    availSyscallDict  = dict()
    syscalls = list(runcSyscallDict.keys())
    cnt=0
    for syscallName in syscalls:
#        if hostSyscallDict.get(syscallName,0)/containerSyscallDict[syscallName] > 1 :
#            availSyscallDict[syscallName] = 1
#        else:
#            availSyscallDict[syscallName] = hostSyscallDict.get(syscallName,0)/containerSyscallDict[syscallName]
#        if availSyscallDict[syscallName] > 0:
#            print(syscallName)
#            cnt += 1
        availSyscallDict[syscallName] = scSyscallDict.get(syscallName,0)/runcSyscallDict[syscallName]
    print(cnt)

    return availSyscallDict

def SaveDict(targetDict,path):
    with open(path,"wb") as f:
        pickle.dump(targetDict, f)

def SyscallUsageDetailInfo(linux_syscallDict, scSyscallCntDict, runcSyscallCntDict):
    detailFile = open("/opt/volume/syscall_use.csv","w")
    for syscall in linux_syscallDict:
        record = linux_syscallDict+"," + scSyscallCntDict[syscall] + "," + runcSyscallCntDict[syscall] + "\n"
        detailFile.write(record)
    close(detailFile)
    

if __name__ == "__main__":

    linux_syscallDict = GetLinuxSyscallDict()
    print("host system call tracing file function cnt...")
    scSyscallCntDict = MakeSyscallCntDict("/opt/volume/security_container/ftrace.txt",linux_syscallDict)
    print("container system call tracing file function cnt...")
    runcSyscallCntDict = MakeSyscallCntDict("/opt/volume/runc_container/ftrace.txt",linux_syscallDict)
    
    availSyscallDict = MakeAvailSyscallDict(scSyscallCntDict, runcSyscallCntDict)
    print(availSyscallDict)

    availSyscallSavePath = "/opt/volume/availSyscallDict.sav"
    SaveDict(availSyscallDict, availSyscallSavePath)
    SyscallUsageDetailInfo(linux_syscallDict, scSyscallCntDict, runcSyscallCntDict)    
