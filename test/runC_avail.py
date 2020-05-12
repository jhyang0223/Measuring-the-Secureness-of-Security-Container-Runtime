import pickle

availDict = dict()
seccompList = list()
syscallList = list()
with open("inseccomp.txt","r") as f:
    for line in f.readlines():
        seccompList.append(line.strip("\n"))

with open("syscall_list.txt","r") as f:
    for line in f.readlines():
        syscallList.append(line.strip("\n"))

for seccompSyscall in seccompList:
    if seccompSyscall in syscallList :
        syscallList.remove(seccompSyscall)

for syscall in syscallList:
    availDict[syscall] = 1.0

with open("availSyscallDict.sav","wb") as f:
        pickle.dump(availDict, f)
