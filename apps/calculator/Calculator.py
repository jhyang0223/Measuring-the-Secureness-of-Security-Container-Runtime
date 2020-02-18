#-*- coding: utf-8 -*-
import os
import sys
import re
import pickle
from datetime import datetime
#get exploit dictionary from pickle save file
def GetExploitDict(path):
    with open(path,"rb") as f:
        exploitDict = pickle.load(f)

    return exploitDict

#convert ftrace result to function name set
def GetFuncNamefromFtrace(path):
    ftraceSet = set()
    ftraceFile = open(path,"r")

    lFormat = re.compile('.*: (.*) <-(.*)')
    for line in ftraceFile:
        searchRet = lFormat.search(line.strip("\n"))
        if searchRet is not None :
            ftraceSet.update([searchRet.group(1),searchRet.group(2)])
    ftraceFile.close()
    return ftraceSet

#convert strace result to function name set
def GetFuncNamefromStrace(path):
    straceSet = set()    
    straceFile = open(path,"r")

    lFormat = re.compile("[0-9]* ([a-zA-Z0-9_]*)\(.*")
    for line in straceFile:
        searchRet = lFormat.search(line.strip("\n"))
        if searchRet is not None :
            straceSet.add(searchRet.group(1))
    straceFile.close()
    return straceSet

#compare trace function name set and 
#return vulnerable function count
def GetVulnerableFuncCount(traceSet, funcStrList):
    funcCount = 0

    for FuncName in traceSet:
        FuncStr = FuncName.strip(" ") + "()"
        if FuncStr in funcStrList:
            funcCount +=1

    return funcCount

#load ftrace file and get 
def GetScore(funcStrList):
    print("##Start Network Test Program")
    print("start ftrace analysis")
    #processing ftrace result
    ftraceFilePath = "/opt/volume/net_ftrace.txt"
    ftraceSet = GetFuncNamefromFtrace(ftraceFilePath)
    ftraceFuncCount = len(ftraceSet)
    ftraceVulnerableCount = GetVulnerableFuncCount(ftraceSet,funcStrList)
    
    print("start strace analysis")
    #processing strace result
    straceFilePath = "/opt/volume/net_strace.txt"
    straceSet = GetFuncNamefromStrace(straceFilePath)
    straceFuncCount = len(straceSet)
    straceVulnerableCount = GetVulnerableFuncCount(straceSet, funcStrList)
    
    print("##Start FS Test Program")
    print("start ftrace analysis")
    #processing ftrace result
    ftraceFilePath = "/opt/volume/fs_ftrace.txt"
    ftraceSet = GetFuncNamefromFtrace(ftraceFilePath)
    ftraceFuncCount = len(ftraceSet)
    ftraceVulnerableCount = GetVulnerableFuncCount(ftraceSet,funcStrList)

    print("start strace analysis")
    #processing strace result
    straceFilePath = "/opt/volume/fs_strace.txt"
    straceSet = GetFuncNamefromStrace(straceFilePath)
    straceFuncCount = len(straceSet)
    straceVulnerableCount = GetVulnerableFuncCount(straceSet, funcStrList)

    
    #calculation equation
    ioScore =0

    #debug
    print("ftraceFuncCount:", ftraceFuncCount)
    print("ftraceVulnerableCount:",ftraceVulnerableCount)
    print("funcStrList:",len(funcStrList))
    print("straceFuncCount:",straceFuncCount)
    print("straceVulnerableCount:",straceVulnerableCount)
    return ioScore

#main
if __name__== "__main__":
    today = datetime.today().strftime("%Y%m%d")

    exploitDictPath = "/opt/volume/exploitDict_"+today+".sav"
    exploitDict = GetExploitDict(exploitDictPath)
    
    score  = GetScore(list())
    print(score)
