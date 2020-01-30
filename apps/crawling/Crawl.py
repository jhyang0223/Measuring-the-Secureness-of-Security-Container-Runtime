#-*- coding: utf-8 -*-
import os
import sys
import requests
import re
from bs4 import BeautifulSoup
import pickle
import subprocess
import io
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
    #get result of command(searchsploit linux kernel)
    cmd = 'searchsploit -w linux kernel | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g"'
    ccmd = 'searchsploit -w linux kernel | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" > /opt/volume/test.txt'
    os.system(ccmd)
    searchResult = subprocess.check_output(cmd,shell=True).decode().strip("\n")
#    searchResultIO = searchResult.split("\n")
    searchResultIO = io.StringIO(searchResult)
    
    lFormat = re.compile('Linux Kernel(.*) - (.*)\| (.*\/([0-9]*))',re.I)
    for line in searchResultIO.readlines():
        searchRet = lFormat.search(line.strip("\n"))
        if searchRet is not None:
            version = searchRet.group(1)
            title = searchRet.group(2).strip(" ")
            codePath = searchRet.group(3).strip(" ")
            exploitID = searchRet.group(4)

            exploitDict[exploitID] = dict()
            exploitDict[exploitID]['title'] = title
            exploitDict[exploitID]['codePath'] = codePath
            exploitDict[exploitID]['version'] = version
    return exploitDict

def SaveExploitDict(exploitDict,path):
    with open(path,"wb") as f:
        pickle.dump(exploitDict, f)
#main
if __name__ == "__main__":
   # if os.path.exists("/opt/volume/dataDict.sav"):
   #     with open("/opt/volume/dataDict.sav","rb") as f:
   #         exploitDict = pickle.load(f)
   # else:
    initDict = InitExploitDict()

    SaveExploitDict(initDict, "/opt/volume/initDict.sav")
