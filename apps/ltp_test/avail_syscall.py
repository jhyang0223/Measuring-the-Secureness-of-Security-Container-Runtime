from typing import Any
import subprocess
import os
import io
import pickle
from typing import Any

import glob
import re

def MakeSyscallCntDict(fileList):
    template = "([a-zA-Z0-9_]+)\(.*\) = [0-9]+"
    compiled = re.compile(template)
    syscallCntDict = dict()
    for straceFilePath in fileList:
        with open(straceFilePath) as straceFile:
            for straceLine in straceFile.readlines():
                retMatch = compiled.match(straceLine)
                if retMatch != None:
                    syscall = retMatch.group(1)
                    if syscallCntDict.get(syscall) == None:
                        syscallCntDict[syscall] =0
                    syscallCntDict[syscall]+=1

    return syscallCntDict

def MakeAvailSyscallDict(hostSyscallDict, containerSyscallDict):
    availSyscallDict  = dict()
    syscalls = list(containerSyscallDict.keys())
    cnt=0
    for syscallName in syscalls:
        if hostSyscallDict.get(syscallName,0)/containerSyscallDict[syscallName] > 1 :
            availSyscallDict[syscallName] = 1
        else:
            availSyscallDict[syscallName] = hostSyscallDict.get(syscallName,0)/containerSyscallDict[syscallName]
        if availSyscallDict[syscallName] > 0:
            print(syscallName)
            cnt += 1
    print(cnt)

    return availSyscallDict
def SaveDict(targetDict,path):
    with open(path,"wb") as f:
        pickle.dump(targetDict, f)

if __name__ == "__main__":
    hostFileList = glob.glob("/opt/volume/host/*")
    containerFileList = glob.glob("/opt/volume/container/*")

    print("host system call tracing file function cnt...")
    hostSyscallCntDict = MakeSyscallCntDict(hostFileList)
    print("container system call tracing file function cnt...")
    containerSyscallCntDict = MakeSyscallCntDict(containerFileList)
    
    availSyscallDict = MakeAvailSyscallDict(hostSyscallCntDict, containerSyscallCntDict)
    print(availSyscallDict)
    availSyscallSavePath = "/opt/volume/availSyscallDict.sav"
    SaveDict(availSyscallDict, availSyscallSavePath)
    
