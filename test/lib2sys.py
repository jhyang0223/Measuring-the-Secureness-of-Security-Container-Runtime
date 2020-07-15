import re
import sys
import subprocess
import pprint
import os
#This Function is to make assembly language library function information dictionary
#Input#
#libFile : library assembly file made by objdump
#output#
#funcInstDict : {'walker': [['mov', '(%rdi)', '%rax'], ...,], 'sample':[], ...}
def CreateLibFuncInfo(libFile):
    funcNameRegex  = re.compile('[0-9A-Fa-f]+ <([a-zA-Z0-9_]+.*)>:')
    funcCodeRegex   = re.compile('\s+[0-9A-Fa-f]+:\s+([0-9A-Fa-f]+ )+\s+(mov|callq|jmpq|syscall)\s+(.*)') 
    
    funcInstDict = dict()
    currentFunc = ''    
    for line in libFile.readlines():
        funcNameLine = funcNameRegex.match(line.strip("\n"))
        if funcNameLine != None:
            funcName = funcNameLine.group(1)
            funcInstDict[funcName] = list()
            currentFunc = funcName
            continue

        funcCodeLine = funcCodeRegex.match(line.strip("\n"))
        if funcCodeLine != None:
            instruction = funcCodeLine.group(2)
            instInfoList = list()
            if instruction == 'syscall':
                instInfoList.append(instruction)
            elif instruction == 'mov':
                registerInfo = funcCodeLine.group(3)
                instInfoList.append(instruction)
                instInfoList.extend(registerInfo.split(","))
            elif instruction == 'jmpq' or instruction == 'callq':
                destFuncRegex = re.compile('.*<([a-zA-Z_]+[a-zA-Z0-9\.@_\-]+)>')
                toFunction = destFuncRegex.match(funcCodeLine.group(3))
                if toFunction != None:
                    instInfoList.append(instruction)
                    instInfoList.append(toFunction.group(1))
            
            if instInfoList !=[]:    
                funcInstDict[currentFunc].append(instInfoList)
            
    return funcInstDict


def IsHex(s):
    try:
        int(s,16)
        return True
    except ValueError:
        return False
  
def FuncInstDataCleansing(funcInstDict):
    funcInfoDict  = dict()
    for func, instList in funcInstDict.items():
        funcInfoDict[func] = dict()
        funcInfoDict[func]['pointer'] = list()
        funcInfoDict[func]['syscall'] = list()
        sysBool = 0
        for instruction in instList:
            if instruction[0] == 'callq' or instruction[0] == 'jmpq':
                funcInfoDict[func]['pointer'].append(instruction[1])
            elif instruction[0] == 'syscall':
                sysBool = 1
        funcInfoDict[func]['sysBool'] = sysBool

    for func,instList in funcInstDict.items():
        if funcInfoDict[func]['sysBool'] == 1:
            instList.reverse()
            sysInst = 0
            for idx,instruction in enumerate(instList):
                if instruction[0] == 'syscall':
                    sysInst = 1
                elif instruction[0] == 'mov' and sysInst ==1:
                    if instruction[2] == '%eax' and IsHex(instruction[1].strip('$')) == True:
                        funcInfoDict[func]['syscall'].append(instruction[1].strip('$'))
                        sysInst = 0
                    elif instruction[2] == '%eax' and IsHex(instruction[1].strip('$')) == False:
                        for i in range(idx+1,len(instList)):
                            if instList[i][0] == 'mov' and instList[i][2] == instruction[1] and IsHex(instList[i][1].strip('$')) == True:
                                funcInfoDict[func]['syscall'].append(instList[i][1].strip('$'))
                                break
                            i+=1
                        sysInst = 0
    return funcInfoDict

def PrintUsedSyscall(funcInfo,funcInfoDict,calledLibCallList,usedSyscallSet):
    if funcInfo['sysBool'] != 0:
        for syscall in funcInfo['syscall']:
            usedSyscallSet.add(syscall)
    for libcall in funcInfo['pointer']:
        if libcall != '__libc_resp':
            if libcall in calledLibCallList:
                continue
            
            calledLibCallList.append(libcall)
            PrintUsedSyscall(funcInfoDict[libcall],funcInfoDict,calledLibCallList,usedSyscallSet)
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("python3 lib2sys.py [object file]")
        print("python3 lib2sys.py test")
        exit(1)
    sys.setrecursionlimit(10000)

    objFilePath = sys.argv[1]
    objDisPath = objFilePath + '.dis'

    cmd = 'objdump -DS '+objFilePath + '> ' + objDisPath
    os.system(cmd)
    objDis = open(objDisPath,'r')
    
    funcInstDict = dict()
    funcInstDict.update(CreateLibFuncInfo(objDis))
    
    funcInfoDict = FuncInstDataCleansing(funcInstDict)
    calledLibCallList = list()
    usedSyscallSet = set()
    PrintUsedSyscall(funcInfoDict['main'],funcInfoDict,calledLibCallList,usedSyscallSet)
    print(usedSyscallSet)
    

    
