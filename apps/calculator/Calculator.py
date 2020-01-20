#-*- coding: utf-8 -*-
import os
import sys
import re
import pickle

#get function name string list from pickle save file
def GetFuncStrList(path):
    with open(path,"rb") as f:
        funcStrList = pickle.load(f)

    return funcStrList

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
def GetIOScore(_type,funcStrList):
    #processing ftrace result
    ftraceFilePath = "/opt/volume/"+_type+"_ftrace.txt"
    ftraceSet = GetFuncNamefromFtrace(ftraceFilePath)
    ftraceFuncCount = len(ftraceSet)
    ftraceVulnerableCount = GetVulnerableFuncCount(ftraceSet,funcStrList)
    
    print("end ftrace analysis")
    #processing strace result
    straceFilePath = "/opt/volume/"+_type+"_strace.txt"
    straceSet = GetFuncNamefromStrace(straceFilePath)
    straceFuncCount = len(straceSet)
    straceVulnerableCount = GetVulnerableFuncCount(straceSet, funcStrList)
    
    #calculation equation
    ioScore =(ftraceVulnerableCount + straceVulnerableCount)/(ftraceFuncCount + straceFuncCount)

    #debug
    print("ftraceFuncCount:", ftraceFuncCount)
    print("ftraceVulnerableCount:",ftraceVulnerableCount)
    print("funcStrList:",len(funcStrList))
    print("straceFuncCount:",straceFuncCount)
    print("straceVulnerableCount:",straceVulnerableCount)
    return ioScore

#main
if __name__== "__main__":
    funcStrList = list(set(GetFuncStrList("/opt/volume/funcStrList.sav")))
    
    fsScore  = GetIOScore("fs",funcStrList)
    
    #netScore = GetIOScore("net",funcStrList)
