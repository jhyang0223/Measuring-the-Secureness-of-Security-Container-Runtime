#-*- coding: utf-8 -*-
import os
import sys
import requests
import re
import pickle
import subprocess
import io
from datetime import datetime
import pandas as pd
from math import log

#Make CVE document dictionary for system call weight
def MakeCVEdocDict(exploitDict):
    CVEdocDict = dict()
    for exploitID, informDict in exploitDict.items():
        syscallDoc = ''
        relatedCVE = ''
        for syscall  in informDict['syscallStrList']:
            syscallDoc += syscall +" "
        if informDict['relatedCVE'] !='':
            relatedCVE = informDict['relatedCVE']
        else:
            relatedCVE = exploitID
        
        if CVEdocDict.get(relatedCVE) == None :
            CVEdocDict[relatedCVE] = ''
        
        CVEdocDict[relatedCVE] +=syscallDoc

    return CVEdocDict

def TF(word, doc):
    return doc.count(word)

def TF_test(wordList,docs,N):
    tfResult = list()
    for i in range(N):
        tfResult.append(list())
        doc = docs[i]
        for j in range(len(wordList)):
            word = wordList[j]
            tfResult[-1].append(TF(word,doc))
    tfFrame = pd.DataFrame(tfResult,columns = wordList)
    return tfFrame

def IDF(word,docs,N):
    df = 0
    for doc in docs:
        df += word in doc
    return log(N/(df+1))

def IDF_test(wordList,docs,N):
    idfResult = list()
    for j in range(len(wordList)):
        word = wordList[j]
        idfResult.append(IDF(word,docs,N))
    idfFrame = pd.DataFrame(idfResult,index = wordList,columns=['IDF'])
    return idfFrame

def TFIDF(word, doc, docs,N):
    return TF(word,doc) * IDF (word, docs,N)

def GetTFIDF(CVEdocDict):
    N = len(CVEdocDict)
    tfResult = list()
    docs = list(CVEdocDict.values())
    wordList = list(set(word for doc in docs for word in doc.split()))
    wordList.sort()
    
    sysweightDict = dict()

    tfFrame = TF_test(wordList,docs,N)
    #print(tfFrame)

    idfFrame = IDF_test(wordList,docs,N)
        
#    print(idfFrame.sort_values(by=['IDF']))
    
    tfidfResult = list()
    for i in range(N):
        tfidfResult.append([])
        doc = docs[i]
        for j in range(len(wordList)):
            word = wordList[j]
            tfidfResult[-1].append(TFIDF(word,doc,docs,N))
    tfidfFrame = pd.DataFrame(tfidfResult,columns=wordList)
    print(tfidfFrame.mean(axis=0).sort_values())
    
    return sysweightDict
#save system call weight dict to pickle save file
def SaveSysweightDict(exploitDict,path):
    with open(path,"wb") as f:
        pickle.dump(exploitDict, f)
#main
if __name__ == "__main__":
    today = datetime.today().strftime("%Y%m%d")
    pd.set_option('display.max_rows', None)    
    exploitDictPath = "/opt/volume/exploitDict_"+today+".sav"
    with open(exploitDictPath,"rb") as f:
        exploitDict = pickle.load(f)
    CVEdocDict = MakeCVEdocDict(exploitDict)
    sysweightDict = GetTFIDF(CVEdocDict)
            
    SysweightDictPath = "/opt/volume/sysweightDict_"+today+".sav"
