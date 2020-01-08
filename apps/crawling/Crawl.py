#-*- coding: utf-8 -*-

import sys
import requests
import re
from bs4 import BeautifulSoup

if __name__ == "__main__":
    #get html file of cve data (mitre)
    dataSet = requests.get("https://cve.mitre.org/data/downloads/allitems.html")
    
    soup = BeautifulSoup(dataSet.content, 'html.parser')
    allDescription = soup.find_all('p')
    descList=list(allDescription)

    functionList = list()
    for one in descList:
        description=one
        
        if "()" in str(description):
            function = description
            functionList.append(function)

    print(functionList)
    
    
