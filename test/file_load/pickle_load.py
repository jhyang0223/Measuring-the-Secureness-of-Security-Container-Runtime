import pickle
import os
from datetime import datetime

if __name__=='__main__':
    today = datetime.today().strftime("%Y%m%d")
    sysRiskDictPath = "/opt/volume/sysRiskDict_"+today+".sav"
    if os.path.exists(sysRiskDictPath):
        with open(sysRiskDictPath,"rb") as f:
            sysRiskDict = pickle.load(f)

    sortedFreqDict = sorted(sysRiskDict.items(),key=(lambda x:x[1]),reverse=True)
    
    for key,value in sortedFreqDict:
        print(key,"-",value)


    #print(sysRiskDict)
