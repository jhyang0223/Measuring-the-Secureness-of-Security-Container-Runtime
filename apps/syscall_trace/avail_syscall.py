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

def MakeSyscallCntDict_host(ftraceFilePath,linux_syscallDict):
    sys_exitT = ".+ sys_exit: NR ([0-9]+) = ([-0-9]+)"   #'.+\(([0-9 ]+)\) .+: sys_(.+)\(.+\)'
    sys_exitCompiled = re.compile(sys_exitT)

    forkT = '.+ \(([0-9 ]+)\) .+: sched_process_fork: comm=.+ pid=.+ child_comm=.+ child_pid=(.+)'
    forkCompiled = re.compile(forkT)

    syscallCntDict = dict()
    ret_1CntDict = dict()

    for ftraceFileName in glob.glob(ftraceFilePath):
        with open(ftraceFileName,"r") as ftraceFile:
            for ftraceLine in ftraceFile.readlines():
                sys_exitRet = sys_exitCompiled.search(ftraceLine)
                if sys_exitRet != None:
                    syscallNum = sys_exitRet.group(1)
                    retVal = sys_exitRet.group(2)
                    if int(syscallNum) > len(linux_syscallDict):
                        continue
                    syscall = linux_syscallDict[syscallNum]
                    if retVal == "-1":
                        if ret_1CntDict.get(syscall) == None:
                            ret_1CntDict[syscall] = 0
                        syscallCntDict[syscall] +=1
                    if syscallCntDict.get(syscall) == None:
#                        print(syscall)
                        syscallCntDict[syscall] =0
                    syscallCntDict[syscall]+=1

    return syscallCntDict

#make syscall count dictionary for security container runtime
def MakeSyscallCntDict_SCR(ftraceFilePath,linux_syscallDict):
    sys_exitT = ".+\(([0-9 ]+)\).+: sys_exit: NR ([0-9]+) = ([-0-9]+)"  #'.+\(([0-9 ]+)\).+: sys_(.+)\(.+\)'
    sys_exitCompiled = re.compile(sys_exitT)

    forkT = '.+\(([0-9 ]+)\).+: sched_process_fork: comm=.+ pid=.+ child_comm=.+ child_pid=(.+)'
    forkCompiled = re.compile(forkT)

    syscallCntDict = dict()
    tgidChildDict = dict()
    tgidSyscallCntDict = dict()
    cmt =0

    ret_1CntDict = dict()

    for ftraceFileName in glob.glob(ftraceFilePath):
        with open(ftraceFileName,"r") as ftraceFile:
            cmt += 1
            print(cmt, ftraceFileName)
            for ftraceLine in ftraceFile.readlines():
                sys_exitRet = sys_exitCompiled.search(ftraceLine.strip('\n'))
#                print('sys_exitRet', sys_exitRet)
                if sys_exitRet != None:
                    tgid = sys_exitRet.group(1)
                    syscallNum = sys_exitRet.group(2)
                    retVal  = sys_exitRet.group(3) 
                    
                        
                    if int(syscallNum) > len(linux_syscallDict):
                        continue  
                    syscall = linux_syscallDict[syscallNum]
                    if retVal == "-1":
                        if ret_1CntDict.get(syscall) == None:
                            ret_1CntDict[syscall] = 0
                        ret_1CntDict[syscall] +=1
                    else:
                        if syscallCntDict.get(syscall) == None:
#                            print(syscall)
                            syscallCntDict[syscall] = 0
                        syscallCntDict[syscall]+=1

                        if tgidSyscallCntDict.get(tgid) == None:
                            tgidSyscallCntDict[tgid] = dict()
                        if tgidSyscallCntDict[tgid].get(syscall) == None:
                            tgidSyscallCntDict[tgid][syscall] = 0
                        tgidSyscallCntDict[tgid][syscall] += 1
                    continue

                forkRet = forkCompiled.search(ftraceLine.strip('\n'))
                if forkRet != None:
                    parentTgid = forkRet.group(1)
                    childPid = forkRet.group(2)
                    if tgidChildDict.get(parentTgid) == None:
                        tgidChildDict[parentTgid] = list()
                    tgidChildDict[parentTgid].append(childPid)

    return syscallCntDict, tgidChildDict, tgidSyscallCntDict

def MakeSyscallCntDict_program(straceFilePath, linux_syscallDict):
    straceT = "([a-zA-Z0-9_]+)\(.*\)\s+=\s+([-0-9]+)"
    straceCompiled = re.compile(straceT)
    syscallCntDict = dict()
    ret_1CntDict = dict()

    for straceFileName in glob.glob(straceFilePath):
        with open(straceFileName,"r") as straceFile:
            for straceLine in straceFile.readlines():
                retMatch = straceCompiled.match(straceLine)
                if retMatch !=None:
                    syscall = retMatch.group(1)
                    retVal = retMatch.group(2)
                    if retVal == "-1":
                        if ret_1CntDict.get(syscall) == None:
                            ret_1CntDict[syscall] = 0
                        ret_1CntDict[syscall] +=1
                    if syscallCntDict.get(syscall) == None:
                        syscallCntDict[syscall] = 0
                    syscallCntDict[syscall] += 1
    
    return syscallCntDict

def MakeAvailSyscallDict(scSyscallDict, progSyscallDict,linux_syscallDict):
    availSyscallDict  = dict()
    syscalls = list(linux_syscallDict.values())
    cnt=0
    for syscallName in syscalls:
        if scSyscallDict.get(syscallName) ==None and progSyscallDict.get(syscallName) == None:
            availSyscallDict[syscallName] = 0

        elif scSyscallDict.get(syscallName) !=None and progSyscallDict.get(syscallName) == None:
            availSyscallDict[syscallName] = 1
        elif scSyscallDict.get(syscallName,0)/progSyscallDict[syscallName] > 1 :
            availSyscallDict[syscallName] = 1
        else:
            availSyscallDict[syscallName] = scSyscallDict.get(syscallName,0)/progSyscallDict[syscallName]
#        if availSyscallDict[syscallName] > 0:
#            print(syscallName)
#            cnt += 1
#        availSyscallDict[syscallName] = scSyscallDict.get(syscallName,0)/runcSyscallDict[syscallName]
#    print(cnt)

    return availSyscallDict

def SaveDict(targetDict,path):
    with open(path,"wb") as f:
        pickle.dump(targetDict, f)

def SyscallUsageDetailInfo(linux_syscallDict, scSyscallCntDict, hostSyscallCntDict, progSyscallCntDict):
    detailFile = open("/opt/volume/syscall_use.csv","w")
#    print(linux_syscallDict.values())
    detailFile.write('system call,host,program,security container\n')
    for syscall in linux_syscallDict.values():
        record = syscall + "," + str(hostSyscallCntDict.get(syscall,0)) + "," + str(progSyscallCntDict.get(syscall,0)) +"," + str(scSyscallCntDict.get(syscall,0)) + "\n"
        detailFile.write(record)
    detailFile.close()
    
def PrintSyscallCntByProc(tgidChildDict, tgidSyscallCntDict, procInfoDict):
    for tgid, syscallCntDict  in tgidSyscallCntDict.items():
        tgidInfo = ''
        for procInfo,procList in  procInfoDict.items():
            if tgid in procList:
                tgidInfo = procInfo
                break
        if tgidInfo == '':
            for parent_tgid, childList in tgidChildDict.items():
                if tgid in childList:
                    tgidInfo = 'child of ' + parent_tgid
                    break

        if tgidInfo == '':
            continue

#        print("**",tgid,tgidInfo,"**")
#        print(syscallCntDict)
#        print('\n\n')

#big file is bigger than 1GB...
def BigFileSplit(dirPath):
    cmd = "find "+dirPath +" -size +1000000k"
    #bigFileList = ["/opt/volume/security_container/epoll.txt", "/opt/volume/security_container/fork.txt", ...]
    try:
        cmdOut = subprocess.check_output(cmd,shell=True)
        bigFileList = cmdOut.decode().strip('\n').split('\n')
        print(bigFileList)
        #bigFile = "/opt/volume/security_container/epoll.txt"
        for bigFile in bigFileList:
            filePrefix = bigFile.strip(".txt") # filePrefix = "/opt/volume/security_container/epoll"
            cmd = 'split -l 300000 --additional-suffix=.txt '+ bigFile + " " + filePrefix +"_"
            os.system(cmd)
            cmd = "rm "+ bigFile
            os.system(cmd)
            print("rm ",bigFile)
    except subprocess.CalledProcessError:
        print("There is big file in this directory")

    
if __name__ == "__main__":

    linux_syscallDict = GetLinuxSyscallDict()
    print("security container runtime system call tracing file function cnt...")
    BigFileSplit("/opt/volume/security_container/*")
    BigFileSplit("/opt/volume/program/*")
    BigFileSplit("/opt/volume/host/*")
    scSyscallCntDict, tgidChildDict, tgidSyscallCntDict = MakeSyscallCntDict_SCR("/opt/volume/security_container/*.txt",linux_syscallDict)
    
    print("test program system call tracing file function cnt...")
    hostSyscallCntDict = MakeSyscallCntDict_host("/opt/volume/host/*",linux_syscallDict)
    print("test program in container system call tracing file function cnt by strace...")
    progSyscallCntDict = MakeSyscallCntDict_program("/opt/volume/program/*",linux_syscallDict)

    availSyscallDict = MakeAvailSyscallDict(scSyscallCntDict, hostSyscallCntDict,linux_syscallDict)
#    print(availSyscallDict)

    availSyscallSavePath = "/opt/volume/availSyscallDict.sav"
    SaveDict(availSyscallDict, availSyscallSavePath)
    SyscallUsageDetailInfo(linux_syscallDict, scSyscallCntDict, hostSyscallCntDict,progSyscallCntDict)    

    procInfoDictPath = "/opt/volume/security_container/procInfoDict.sav"
    if os.path.exists(procInfoDictPath):
        with open(procInfoDictPath,"rb") as f:
            procInfoDict = pickle.load(f)
    else:
        print("no /opt/volume/security_container/procInfoDict.sav")
        exit(1)
        
    PrintSyscallCntByProc(tgidChildDict, tgidSyscallCntDict, procInfoDict)
    
