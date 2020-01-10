#-*- coding: utf-8 -*-
import os
import sys
import requests
import re
from bs4 import BeautifulSoup
import pickle

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

#main
if __name__ == "__main__":
    if os.path.exists("/opt/volume/dataDict.sav"):
        with open("/opt/volume/dataDict.sav","rb") as f:
            dataDict = pickle.load(f)
    else:
        dataDict = CreateCVE_DescDict()

    cutDataDict = Cutin5years(dataDict)
    
        
    funcStrList = ExtractFuncStr(cutDataDict)
    print(funcStrList)

    SaveFuncStrList(funcStrList)
