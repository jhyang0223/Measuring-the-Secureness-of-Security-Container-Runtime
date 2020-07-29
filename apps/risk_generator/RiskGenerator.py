#-*- coding: utf-8 -*-
import os
import sys
import requests
import re
import pickle
import subprocess
import io
from datetime import datetime

import copy
from bs4 import BeautifulSoup
import pandas as pd
from math import log
import numpy as np

#save exploit dict to pickle save file
def SaveDict(myDict,path):
    with open(path,"wb") as f:
        pickle.dump(myDict, f)

def AddCVEInfo(syscallUseDict):
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.3'}

    exploitIDwithoutCVE = list()
    #regular expression to get cve name from exploit code web page
    cveFormat = re.compile('.*(CVE-[0-9]*-[0-9]*).*',re.I)    
    #loop for each exploit ID 
    for exploitID, informDict in syscallUseDict.items():
        #request exploit code web page in exploit-db
        pathHtml = requests.get(informDict['codePath'],headers=headers)

        #set beautifulsoup and get exploit code and cve name
        soup = BeautifulSoup(pathHtml.content, 'html.parser')
        codeStr  = soup.find('code').text
        searchRet = cveFormat.search(soup.find('meta',attrs={'name':'keywords'}).get('content'))
        relatedCVE = ''
        if searchRet is not None :
            relatedCVE = searchRet.group(1)
        else:
            exploitIDwithoutCVE.append(exploitID)
            continue

        syscallUseDict[exploitID]['relatedCVE'] = relatedCVE

    #delete exploit code that does not have related cve
    for exploitID in exploitIDwithoutCVE:
        print("del:",exploitID)
        del syscallUseDict[exploitID]

##################################################################################
###-------------------------System Call Weighting functions--------------------###
##################################################################################

#Make CVE document dictionary for system call weight
def MakeCVEdocDict(exploitDict):
    CVEdocDict = dict()
    for exploitID, informDict in exploitDict.items():
        syscallDoc = ''
        relatedCVE = ''
        print(exploitID,informDict['used_syscall'])
        for syscall  in informDict['used_syscall']:
            syscallDoc += syscall +" "
        if informDict['relatedCVE'] !='':
            relatedCVE = informDict['relatedCVE']
        else:
            relatedCVE = exploitID
        
        if CVEdocDict.get(relatedCVE) == None :
            CVEdocDict[relatedCVE] = ''
        
        CVEdocDict[relatedCVE] +=syscallDoc

    return CVEdocDict

def IsPatched(patchUrl):
    if patchUrl == None:
        return None
    else: 
        return patchUrl.replace("https","http")

#month delta
def PublishTimeDelta(publishDate):
    publishDateObj = datetime.strptime(publishDate,"%Y-%m-%d")
#    print(publishDateObj)
    diff = datetime.now() - publishDateObj
#    print(diff.days)
    timeWeight = diff.days//12
    return timeWeight

def MakeCVEWeightDict(CVEdocDict):
    cveList = list(CVEdocDict.keys())
    cveWeightDict = dict()
    noCVSSList = list()
    for cve in cveList:
        webSite = "http://www.cvedetails.com/cve/"+cve
        pathHtml = requests.get(webSite)
#        print(cve)
        soup = BeautifulSoup(pathHtml.content,'html.parser') 
        if soup.find('div','cvssbox') == None:
            noCVSSList.append(cve)
            continue
        cvssScore = soup.find('div','cvssbox').string
        dateNote = soup.find('span',"datenote").string
        publishDate = re.search("Publish Date : ([0-9]+-[0-9]+-[0-9]+)",dateNote).group(1)
        timeWeight = 1.0/float(PublishTimeDelta(publishDate))
            
        cveWeightDict[cve] = float(cvssScore) * timeWeight

    for noCVSS in noCVSSList:
        del CVEdocDict[noCVSS]
    return cveWeightDict
        
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

def GetTFIDF(CVEdocDict,CVEWeightDict):
    N = len(CVEdocDict)
    tfResult = list()
    cveList = list(CVEdocDict.keys())
    docs = list(CVEdocDict.values())
    
    wordList = list(set(word for doc in docs for word in doc.split())) # system call list
    wordList.sort()
        
    wordCntList = list(word for doc in docs for word in doc.split())
    allCnt = len(wordCntList)
    wordFreqDict = dict()
    for word in wordList:
        wordFreqDict[word] = wordCntList.count(word)

    sortedFreqDict = sorted(wordFreqDict.items(),key=(lambda x:x[1]),reverse=True)

    for key,value in sortedFreqDict:
        print(key,"-",value/allCnt)

    sysRiskDict = dict()
    sysweightNoTimeDict = dict()
    tfFrame = TF_test(wordList,docs,N)
    #print(tfFrame)

    idfFrame = IDF_test(wordList,docs,N)
        
    tfidfResult = list()
    tfidfntResult = list()
    for i in range(N):
        tfidfResult.append([])
        tfidfntResult.append([])
        doc = docs[i]
        for j in range(len(wordList)):
            word = wordList[j]
            tfidf = TFIDF(word,doc,docs,N)
            syscallWeight = CVEWeightDict[cveList[i]] * tfidf
            tfidfResult[-1].append(syscallWeight)
            tfidfntResult[-1].append(tfidf)
    tfidfFrame = pd.DataFrame(tfidfResult,columns=wordList)
    tfidfntFrame = pd.DataFrame(tfidfntResult,columns=wordList)
    sysRiskDict = tfidfFrame.mask(tfidfFrame.eq(0)).mean(axis=0,skipna=True).to_dict()

    print(tfidfFrame)

    
    return sysRiskDict

#save system call weight dict to pickle save file
def SaveSysRiskDict(sysweightDict,path):
    with open(path,"wb") as f:
        pickle.dump(sysweightDict, f)

#main
if __name__ == "__main__":
    today = datetime.today().strftime("%Y%m%d")

    syscallUseDictPath = "/opt/volume/syscallUseDict_"+today+".sav"
    if os.path.exists(syscallUseDictPath):
        with open(syscallUseDictPath,"rb") as f:
            syscallUseDict = pickle.load(f)
    else:
        print("error: syscallUseDict does not exist")
        exit(1)

    pd.set_option('display.max_rows', None,'display.max_columns',None)

    addedSyscallUseDictPath = "/opt/volume/addedSyscallUseDict_"+today+".sav"
    if os.path.exists(addedSyscallUseDictPath):
        with open(addedSyscallUseDictPath,"rb") as f:
            syscallUseDict = pickle.load(f)       
    else:
        AddCVEInfo(syscallUseDict)
        SaveSysRiskDict(syscallUseDict,addedSyscallUseDictPath)

    sysRiskDictPath = "/opt/volume/sysRiskDict_"+today+".sav"
    if os.path.exists(sysRiskDictPath):
        with open(sysRiskDictPath,"rb") as f:
            sysRiskDict = pickle.load(f)
    else :
        CVEdocDict = MakeCVEdocDict(syscallUseDict)
        CVEWeightDict = MakeCVEWeightDict(CVEdocDict)
        sysRiskDict = GetTFIDF(CVEdocDict,CVEWeightDict)
        SaveSysRiskDict(sysRiskDict,sysRiskDictPath)
