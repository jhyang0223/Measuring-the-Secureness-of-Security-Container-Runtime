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

################################################################################################################
def CreateCVE_DescDict():
    dataDict=dict()
    
    #get html file of cve data (mitre)
    dataSet = requests.get("https://cve.mitre.org/data/downloads/allitems.html")

    #get cve name list and cve description by using beautifulsoup
    soup = BeautifulSoup(dataSet.content, 'html.parser')
    allTitle = soup.find_all('font',attrs={'size':'+2'})
    allDescription = soup.find_all('p')

    #match cve name - description and make name:description dictionary
    print(len(allTitle))
    for i in range(0,len(allTitle)):
        name = allTitle[i].b.text.replace("Name: ","")
        description = allDescription[i+2].text
        dataDict[name] = description

    #save pickle
    with open('/opt/volume/dataDict.sav',"wb") as f:
        pickle.dump(dataDict, f)

    #return Dictionary
    return dataDict

#To cut before 2015 cve data
def Cutin5years(dataDict):
    return dataDict   

#extract function name string from cve description
def ExtractFuncStr(dataDict):
    funcStrList = list()

    funcRegex= re.compile("[A-Za-z0-9]*\(\)")
    
    for description in dataDict.values():
        oneDescFunc = funcRegex.findall(description)
        if oneDescFunc:
            for funcStr in oneDescFunc:
                funcStrList.append(funcStr)
            
    return funcStrList

#save funcStrList for using it as ftrace function list
def SaveFuncStrList(funcStrList):
    with open("/opt/volume/funcStrList.sav","wb") as f:
        pickle.dump(funcStrList, f)
################################################################################################################
###-------------------------upper functions are cve crawling functions they are not used.--------------------###
################################################################################################################

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
    lFormat = re.compile('.*NR_([0-9a-zA-Z_]*).*')
    
    cmd = '''cat $(printf "#include <sys/syscall.h>\nSYS_read" | gcc -E - | awk '{print $3}' | grep -v -e '^$' | grep -v -e '<' | sed 's/\"//g') | grep "#define" | grep "NR_" | sort -u'''
    catResult = subprocess.check_output(cmd,shell=True).decode().strip("\n")
    catResultIO = io.StringIO(catResult)
    print(catResult)
    for line in catResultIO.readlines():
        searchRet  = lFormat.search(line.strip("\n"))
        if searchRet is not None:
            linux_syscallList.append(searchRet.group(1))

    return linux_syscallList

#find system calls used in the exploit and return used system call list
def FindSyscallStrList(code):
    syscallStrList = list()
    linux_syscallList = GetLinuxSyscallList()
    
    
    
    
    return syscallStrList

def AddDBExploit2Dict(initDict):
    syscallStrList = list()
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.3'}
    exploitDict = copy.deepcopy(initDict)
    cveFormat = re.compile('.*(CVE-[0-9]*-[0-9]*).*',re.I)
    for exploitID, informDict in exploitDict.items():
        pathHtml = requests.get(informDict['codePath'],headers=headers)
        soup = BeautifulSoup(pathHtml.content, 'html.parser')
        codeStr  = soup.find('code').text
        searchRet = cveFormat.search(soup.find('meta',attrs={'name':'keywords'}).get('content'))
        relatedCVE = ''
        if searchRet is not None :
            relatedCVE = searchRet.group(1)
        exploitDict[exploitID]['relatedCVE'] = relatedCVE
        GetLinuxSyscallList()
#        syscallStrList= FindSyscallStrList(codeStr)
#        exploitDict[exploitID]['syscallStrList'] = syscallStrList
    return exploitDict

def AddCveExploit2Dict(exploitDict):
    for exploitID, informDict  in exploitDict.items():
        codeStr = exploitDict[exploitID]['codeStr']
    return exploitDict
def SaveExploitDict(exploitDict,path):
    with open(path,"wb") as f:
        pickle.dump(exploitDict, f)
#main
if __name__ == "__main__":
    today = datetime.today().strftime("%Y%m%d")
    
    initDictPath = "/opt/volume/initDict_"+today+".sav"
    if os.path.exists(initDictPath):
        with open(initDictPath,"rb") as f:
            initDict = pickle.load(f)
    else:
        initDict = InitExploitDict()
        os.system("rm /opt/volume/initDict*")
        SaveExploitDict(initDict, initDictPath)
    
    exploitDict = AddDBExploit2Dict(initDict)
    exploitDictPath = "/opt/volume/exploitDict_"+today+".sav"

#    if os.path.exists(exploitDictPath):
#        with open(exploitDictPath,"rb") as f:
#            exploitDict = pickle.load(f)
#    else:
#        exploitDict = AddDBExploit2Dict(initDict)
#        os.system("rm /opt/volume/exploitDict*")
#        SaveExploitDict(exploitDict, exploitDictPath)


