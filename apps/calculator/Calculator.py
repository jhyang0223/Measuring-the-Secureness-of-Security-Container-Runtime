#-*- coding: utf-8 -*-
import os
import sys
import re
import pickle
from datetime import datetime
#main

def GetScore(sysweightDict, availSyscallDict):
    syscallList = list(availSyscallDict.keys())
    score = 0.0
    for syscall in syscallList:
        score += availSyscallDict[syscall]*sysweightDict.get(syscall,0)
    return score
if __name__== "__main__":
    today = datetime.today().strftime("%Y%m%d")
    sysweightDictPath = "/opt/volume/sysweightDict_"+today+".sav"
    if os.path.exists(sysweightDictPath):
        with open(sysweightDictPath,"rb") as f:
            sysweightDict = pickle.load(f)
    else:
        print("[error] no sysweightDict")
        exit(1)
    availSyscallDictPath = "/opt/volume/availSyscallDict.sav"
    if os.path.exists(availSyscallDictPath):
        with open(availSyscallDictPath,"rb") as f:
            availSyscallDict = pickle.load(f)
    else:
        print("[error] no availSyscallDict")
        exit(1)
    
    score = GetScore(sysweightDict, availSyscallDict)
    print(score)
