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

import pandas as pd
from math import log
import numpy as np

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

#available system call in docker
def GetLinuxSyscallList():
    linux_syscallList = list()
    #system call string is usually '#define .* __NR_(system_call) .*'
    lFormat = re.compile('.*NR_([0-9a-zA-Z_]*).*')
    
    #This command get string in library header file
    cmd = '''cat $(printf "#include <sys/syscall.h>\nSYS_read" | gcc -E - | awk '{print $3}' | grep -v -e '^$' | grep -v -e '<' | sed 's/\"//g') | grep "#define" | grep "NR_" | sort -u'''
    catResult = subprocess.check_output(cmd,shell=True).decode().strip("\n")
    catResultIO = io.StringIO(catResult)

    #examine each line fits to my regular expression
    for line in catResultIO.readlines():
        searchRet  = lFormat.search(line.strip("\n"))
        if searchRet is not None:
            linux_syscallList.append(searchRet.group(1))
    print(len(linux_syscallList))
    return linux_syscallList

#figure system call in function list
def FigureSyscall(funcStrList, linux_syscallList):
    syscallStrList = list()

    for funcStr in funcStrList:
        for syscall in linux_syscallList:
            if funcStr.strip(" ") == syscall:
                syscallStrList.append(syscall)

    return syscallStrList

#find system calls used in the exploit and return used system call list
def FindCodeSyscallStrList(code,linux_syscallList):
    funcStrList = list()
    fFormat=re.compile('''[A-Za-z_][0-9A-Za-z_]+\(.*\)''')
    for funcStr in fFormat.findall(code):
        funcStrList.append(funcStr.split("(")[0])
    
    fFormat_sys = re.compile('''SYS_[A-Za-z_0-9]+''',re.I)
    for funcStr in fFormat_sys.findall(code):
        funcStrList.append(funcStr.split("_")[1])

    fFormat_NR = re.compile('''NR_[A-Za-z_0-9]+''',re.I)
    for funcStr in fFormat_NR.findall(code):
        funcStrList.append(funcStr.split("_")[1])

    #debug
#    print("    exploitCode Data...")
#    print("        functionList : ",funcStrList)
    syscallStrList = FigureSyscall(funcStrList,linux_syscallList)

    #debug
#    print("        syscallStrList : ",syscallStrList)
    return syscallStrList

#find system calls in cve description and return refered system call list
def FindCVEDescSyscallStrList(cveName, linux_syscallList):
    funcStrList = list()
    syscallStrList = list()
    fFormat=re.compile('''[A-Za-z_][0-9A-Za-z_]+\(.*\)''')
    
    webSite = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="+cveName
    pathHtml = requests.get(webSite)
    soup = BeautifulSoup(pathHtml.content, 'html.parser')
    webTextData = soup.find_all('tr')
    i=0
    for i in range(0,len(webTextData)):
        if 'Description' == webTextData[i].text.strip("\n"):
            cveDesc = webTextData[i+1].text
        i+=1

    for funcStr in fFormat.findall(cveDesc):
        funcStrList.append(funcStr.split("(")[0])

    fFormat_sys = re.compile('''SYS_[A-Za-z_0-9]+''',re.I)
    for funcStr in fFormat_sys.findall(cveDesc):
        funcStrList.append(funcStr.split("_")[1])

    fFormat_NR = re.compile('''NR_[A-Za-z_0-9]+''',re.I)
    for funcStr in fFormat_NR.findall(cveDesc):
        funcStrList.append(funcStr.split("_")[1])

    #debug
    print("    cve description data:", cveDesc)
#    print("        functionList : ",funcStrList)
    syscallStrList = FigureSyscall(funcStrList,linux_syscallList)
    syscallStrList.extend(FigureSyscall(cveDesc.split(" "),linux_syscallList))
    #debug
#    print("        syscallStrList : ", syscallStrList)
    if "RESERVED" in cveDesc:
        syscallStrList = ["RESERVED"]
    return syscallStrList

#find system calls in exploit title and return refered system call to list
def FindTitleSyscallStrList(title, linux_syscallList):
    funcStrList = list()
    fFormat=re.compile('''[A-Za-z_][0-9A-Za-z_]+\(.*\)''')
    for funcStr in fFormat.findall(title):
        funcStrList.append(funcStr.split("(")[0])

    fFormat_sys = re.compile('''SYS_[A-Za-z_0-9]+''',re.I)
    for funcStr in fFormat_sys.findall(title):
        funcStrList.append(funcStr.split("_")[1])

    fFormat_NR = re.compile('''NR_[A-Za-z_0-9]+''',re.I)
    for funcStr in fFormat_NR.findall(title):
        funcStrList.append(funcStr.split("_")[1])

    #debug
#    print("    exploit title ...")
#    print("        functionList : ",funcStrList)
    FigureSyscall(title.split(" "),linux_syscallList)
    syscallStrList = FigureSyscall(funcStrList,linux_syscallList)
    syscallStrList.extend(FigureSyscall(title.split(" "),linux_syscallList))
    
    #debug
#    print("        syscallStrList : ", syscallStrList)

    return syscallStrList

def AddCrawlingInfo2Dict(initDict):
    #fake header to get reponse packet from web site
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.3'}
    
    exploitIDwithoutCVE = list()
    exploitDict = copy.deepcopy(initDict)
    freqDict=dict()
    #linux system call list in docker
    linux_syscallList = GetLinuxSyscallList()
    #regular expression to get cve name from exploit code web page
    cveFormat = re.compile('.*(CVE-[0-9]*-[0-9]*).*',re.I)
    #loop for each exploit ID 
    for exploitID, informDict in exploitDict.items():
        #for save found systemcall string in the exploit information
        syscallStrList = list()
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

        exploitDict[exploitID]['relatedCVE'] = relatedCVE
        
        #debug
        print("exploitID : ",exploitID)
        print("    relatedCVE : ",relatedCVE)
        
        #find system calls in exploit code and add to list
        syscallStrList.extend(FindCodeSyscallStrList(codeStr,linux_syscallList))
        
        #find system calls in cve description and add to list
        if relatedCVE != "":
            descSyscallStrList  = FindCVEDescSyscallStrList(relatedCVE,linux_syscallList)
            if "RESERVED" in descSyscallStrList:
                print("RESERVED",exploitID)
                exploitIDwithoutCVE.append(exploitID)
            syscallStrList.extend(descSyscallStrList)
        #find system calls in exploit title
        exploitTitle = informDict['title']
        syscallStrList.extend(FindTitleSyscallStrList(exploitTitle,linux_syscallList))

        #add sytemcall string list, related cve name to exploit dict
        exploitDict[exploitID]['syscallStrList'] = list(set(syscallStrList))
       
        if len(exploitDict[exploitID]['syscallStrList']) == 0 :
            print(exploitID,exploitDict[exploitID]['syscallStrList'])
            exploitIDwithoutCVE.append(exploitID)
        print("    related system call : ", exploitDict[exploitID]['syscallStrList'])

        #count system call frequency
        for syscall  in exploitDict[exploitID]['syscallStrList']:
            if freqDict.get(syscall)==None:
                freqDict[syscall] = 0
            freqDict[syscall] += 1

    #sort system call frequency dict
    sortedFreqDict = sorted(freqDict.items(),key=(lambda x:x[1]),reverse=True)
   
    for exploitID in exploitIDwithoutCVE:
        del exploitDict[exploitID]
    print("exploit count:",len(exploitDict))
    for key,value in sortedFreqDict:
        print(key,"-",value)
    
    return exploitDict


#save exploit dict to pickle save file
def SaveExploitDict(exploitDict,path):
    with open(path,"wb") as f:
        pickle.dump(exploitDict, f)

##################################################################################
###-------------------------System Call Weighting functions--------------------###
##################################################################################

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

def IsPatched(patchUrl):
    if patchUrl == None:
        return None
    else: 
        return patchUrl.replace("https","http")

#month delta
def PublishTimeDelta(publishDate):
    publishDateObj = datetime.strptime(publishDate,"%Y-%m-%d")
    print(publishDateObj)
    diff = datetime.now() - publishDateObj
    print(diff.days)
    timeWeight = diff.days//12
    return timeWeight

def MakeCVEWeightDict(cveList):
    cveWeightDict = dict()
    for cve in cveList:
        webSite = "http://www.cvedetails.com/cve/"+cve
        pathHtml = requests.get(webSite)
        print(cve)
        soup = BeautifulSoup(pathHtml.content,'html.parser') 
        cvssScore = soup.find('div','cvssbox').string
        dateNote = soup.find('span',"datenote").string
        publishDate = re.search("Publish Date : ([0-9]+-[0-9]+-[0-9]+)",dateNote).group(1)
        timeWeight = 1.0/float(PublishTimeDelta(publishDate))
            
        cveWeightDict[cve] = float(cvssScore) #* timeWeight
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
    
    sysweightDict = dict()
    sysweightNoTimeDict = dict()
    tfFrame = TF_test(wordList,docs,N)
    #print(tfFrame)

    idfFrame = IDF_test(wordList,docs,N)
        
#    print(idfFrame.sort_values(by=['IDF']))
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
    sysweightDict = tfidfFrame.mean(axis=0).to_dict()

    print("without time weight-----------------")
    print(tfidfntFrame.mean(axis=0).sort_values())

    print("with time weight-----------------")
    print(tfidfFrame.mean(axis=0).sort_values())
    print("?",sysweightDict)
    
#    print(tfidfFrame)
    
    return sysweightDict

#save system call weight dict to pickle save file
def SaveSysweightDict(sysweightDict,path):
    with open(path,"wb") as f:
        pickle.dump(sysweightDict, f)

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
        SaveExploitDict(initDict, initDictPath)
    
    exploitDictPath = "/opt/volume/exploitDict_"+today+".sav"

    if os.path.exists(exploitDictPath):
        with open(exploitDictPath,"rb") as f:
            exploitDict = pickle.load(f)
    else:
        exploitDict = AddCrawlingInfo2Dict(initDict)
        os.system("rm /opt/volume/exploitDict*")
        SaveExploitDict(exploitDict, exploitDictPath)

    ####System Call Weight Part####
    pd.set_option('display.max_rows', None)    
    CVEdocDict = MakeCVEdocDict(exploitDict)
    CVEWeightDict = MakeCVEWeightDict(list(CVEdocDict.keys()))
    sysweightDict = GetTFIDF(CVEdocDict,CVEWeightDict)
            
    sysweightDictPath = "/opt/volume/sysweightDict_"+today+".sav"
    SaveSysweightDict(sysweightDict,sysweightDictPath)
