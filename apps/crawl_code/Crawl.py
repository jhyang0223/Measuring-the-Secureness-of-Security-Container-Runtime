#-*- coding: utf-8 -*-
import os
import sys
import requests
import re
from bs4 import BeautifulSoup
import pickle
import subprocess
import io
from datetime import datetime

import copy
import glob
import pandas as pd
from math import log
import numpy as np

from pyparsing import Word, alphas, nums, White, LineStart,alphanums,SkipTo,Keyword,Optional,Forward,Literal,delimitedList, cStyleComment,Group,QuotedString,nestedExpr

#####################################################################################
###-------------------------CVE Information Crawling functions--------------------###
#####################################################################################

#searchsploit searching with keyword 'Linux Kernel' and get title string, function strings
def InitExploitDict():
    exploitDict = dict()
    
    #exploit db update
    os.system("searchsploit -u")
    #get result of command(searchsploit linux kernel) and convert to string
    cmd = 'searchsploit -w linux kernel | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g"'
    searchResult = subprocess.check_output(cmd,shell=True).decode().strip("\n")
    searchResultIO = io.StringIO(searchResult)
    
    #line regular expression compile
    lFormat = re.compile('Linux Kernel(.*) - (.*)\| (.*\/([0-9]*))',re.I)
    #examine each line fits to my regular expression
    for line in searchResultIO.readlines():
        searchRet = lFormat.search(line.strip("\n"))
        #if each line fits to regular expression, I extract version, title, code url, exploit id in the line
        if searchRet is not None:
            version = searchRet.group(1)
            title = searchRet.group(2).strip(" ")
            codePath = searchRet.group(3).strip(" ")
            exploitID = searchRet.group(4)
            #save extracted information as dictionary form
            exploitDict[exploitID] = dict()
            exploitDict[exploitID]['title'] = title
            exploitDict[exploitID]['codePath'] = codePath
            exploitDict[exploitID]['version'] = version
    return exploitDict

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

#This Function is to make assembly language library function information dictionary
#Input#
#libFile : library assembly file made by objdump
#output#
#funcInstDict : {'walker': [['mov', '(%rdi)', '%rax'], ...,], 'sample':[], ...}
def CreateLibFuncInfo(libFile):
    funcCodeRegex   = re.compile('\s+[0-9A-Fa-f]+:\s+([0-9A-Fa-f]+ )+\s+(mov|callq|jmpq|syscall)\s+(.*)')
    funcNameRegex  = re.compile('[0-9A-Fa-f]+ <([a-zA-Z0-9_\-]+.*)>:')
    sectionNameRegex  = re.compile('[0-9A-Fa-f]+ <(.+)>:')

    sectionName = 0
    funcInstDict = dict()
    currentFunc = ''
    for line in libFile.readlines():
        funcNameLine = funcNameRegex.match(line.strip("\n"))
        if funcNameLine != None:
            if '@plt' in funcNameLine.group(1):
                sectionName = 1
                continue
            funcName = funcNameLine.group(1).split("@")[0]
            funcInstDict[funcName] = list()
            currentFunc = funcName
            sectionName = 0
            continue

        sectionNameLine = sectionNameRegex.match(line.strip("\n"))
        if sectionNameLine != None or sectionName == 1:
            sectionName = 1
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
                    instInfoList.append(toFunction.group(1).split('@')[0])

            if instInfoList !=[]:
                funcInstDict[currentFunc].append(instInfoList)

    return funcInstDict

#Confirm s is hexadecimal format string
def IsHex(s):
    try:
        int(s,16)
        return True
    except ValueError:
        return False

def FuncInstDataCleansing(funcInstDict):
    funcInfoDict  = dict()
    for rawFunc, instList in funcInstDict.items():
        func = rawFunc.split('@')[0]
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

    for rawFunc,instList in funcInstDict.items():
        func = rawFunc.split('@')[0]
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

def FunctionPointerTracing(pLibcall, lib2sysDict, repeatedLibcallSet):
    usedSyscallSet = set()
    if lib2sysDict[pLibcall]['sysBool'] != 0:
        for syscall in lib2sysDict[pLibcall]['syscall']:
            usedSyscallSet.add(syscall)
    for ppLibcall in lib2sysDict[pLibcall]['pointer']:
        if ppLibcall == '__libc_resp' or ppLibcall in repeatedLibcallSet:
            continue
        repeatedLibcallSet.add(ppLibcall)
        usedSyscallSet.update(FunctionPointerTracing(ppLibcall,lib2sysDict,repeatedLibcallSet))

    return usedSyscallSet

def GetUsedSyscall(usedLibcallList,lib2sysDict):
    usedSyscallSet = set()
    for usedLibcall in usedLibcallList:
        libcall = usedLibcall
        if lib2sysDict.get(usedLibcall) == None:
            havePre = 0
            for pre in ["_IO_","__"]:
                if lib2sysDict.get(pre+usedLibcall) != None:
                    libcall = pre+usedLibcall
                    havePre = 1
                    break
            if havePre == 0:
#                print('NotInLib:',usedLibcall)
                continue
        if lib2sysDict[libcall]['sysBool'] != 0:
            for syscall in lib2sysDict[libcall]['syscall']:
                usedSyscallSet.add(syscall)
        for pLibcall in lib2sysDict[libcall]['pointer']:
            if pLibcall != '__libc_resp':
                repeatedLibcallSet = set([pLibcall])
                usedSyscallSet.update(FunctionPointerTracing(pLibcall, lib2sysDict,repeatedLibcallSet))
                    
    return usedSyscallSet

def Hex2Syscall(usedSyscallSet,linux_syscallDict):
    usedSyscallList = list()
    for syscallHex  in usedSyscallSet:
        syscallInt = int(syscallHex,16)
        syscallStr = linux_syscallDict.get(str(syscallInt))
        if syscallStr != None:
            usedSyscallList.append(syscallStr)    

    return usedSyscallList

def MakeLib2SysDict():
    lib2sysDict = dict()
    cmd = 'objdump -DS /lib/x86_64-linux-gnu/libc.so.6 > libc.dis'
    os.system(cmd)

    cmd = 'objdump -DS /lib/x86_64-linux-gnu/libpthread.so.0 > libpthread.dis'
    os.system(cmd)

    cmd = 'objdump -DS  /lib/x86_64-linux-gnu/libkeyutils.so.1 > libkeyutils.dis'
    os.system(cmd)
    
    cmd = 'objdump -DS /lib64/ld-linux-x86-64.so.2 > ld.dis'
    os.system(cmd)

    if len(glob.glob('*.dis')) > 0:
        for libDisFile in glob.glob('*.dis'):
            libDis = open(libDisFile,'r')
            funcInstDict = dict()
            funcInstDict.update(CreateLibFuncInfo(libDis))
            lib2sysDict.update(FuncInstDataCleansing(funcInstDict))

            libDis.close()
    return lib2sysDict

def LibCallParsing(codeStr):
    usedLibcallList = list()
    cFunction = Word(alphanums+"_")+ "(" + \
 Group( Optional(delimitedList(Word(alphanums+"_"+"="+"*"+" "+"["+"]")|QuotedString('"',multiline=True,escChar="\n")|nestedExpr(opener="{",closer="}"))) ) + ")" +";"
    cFunction.ignore( cStyleComment )
    
    for func in cFunction.searchString(codeStr):
        usedLibcallList.append((func[0]))

    return usedLibcallList

# Return dictionary to save exploit code system call usage
def GetSyscallUseDict(initDict,lib2sysDict):
    syscallUseDict = copy.deepcopy(initDict)
    linux_syscallDict = GetLinuxSyscallDict()
    cmd = "mkdir -p /exploit_code"
    os.system(cmd)

    os.chdir('/exploit_code')
    #loop for each exploit ID
    for exploitID, informDict in syscallUseDict.items():
        #download exploit code in current directory
        cmd = "searchsploit -m " + exploitID + " > /dev/null"
        os.system(cmd)
        
        #if exploit code file type is c
        exploitCode  = glob.glob('*.c')
        if len(exploitCode) > 0:
            cCode = open(exploitCode[0],'r')
            usedLibcallList = LibCallParsing(cCode.read())
            usedLibcallList = list(set(usedLibcallList))
            calledLibCallList = list()
            usedSyscallSet = GetUsedSyscall(usedLibcallList, lib2sysDict)
            syscallUseDict[exploitID]['used_syscall'] = Hex2Syscall(usedSyscallSet,linux_syscallDict)
            print(exploitID,":",syscallUseDict[exploitID]['used_syscall'])
            cCode.close()
        else:
            syscallUseDict[exploitID]['used_syscall'] = []
        cmd = 'rm *'
        os.system(cmd)
                
    return syscallUseDict

#save dict to pickle save file
def SaveDict(myDict,path):
    with open(path,"wb") as f:
        pickle.dump(myDict, f)

#main
if __name__ == "__main__":
    today = datetime.today().strftime("%Y%m%d")
    
    ######Crawling Part######
    initDictPath = "/opt/volume/initDict_"+today+".sav"
    if os.path.exists(initDictPath):
        with open(initDictPath,"rb") as f:
            initDict = pickle.load(f)
    else:
        initDict = InitExploitDict()
        os.system("rm /opt/volume/initDict*")
        SaveDict(initDict, initDictPath)

    lib2sysDictPath = '/opt/volume/lib2sysDict_'+today+".sav"
    if os.path.exists(lib2sysDictPath):
        with open(lib2sysDictPath,"rb") as f:
            lib2sysDict = pickle.load(f)

    else:
        lib2sysDict = MakeLib2SysDict()
        os.system("rm /opt/volume/lib2sysDict*")
        SaveDict(lib2sysDict,lib2sysDictPath)

    syscallUseDictPath = "/opt/volume/syscallUseDict_"+today+".sav"
    if os.path.exists(syscallUseDictPath):
        with open(syscallUseDictPath,"rb") as f:
            syscallUseDict = pickle.load(f)
    else:
        syscallUseDict = GetSyscallUseDict(initDict,lib2sysDict)
        os.system("rm /opt/volume/exploitDict*")
        SaveDict(syscallUseDict, syscallUseDictPath)

