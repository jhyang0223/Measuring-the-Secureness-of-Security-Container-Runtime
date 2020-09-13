import sys
import pickle
from datetime import datetime

if __name__ == "__main__" : 
    today = datetime.today().strftime("%Y%m%d")
    sysRiskDictPath = "/opt/volume/sysRiskDict_"+today+".sav"
    availSyscallDictPath = "/opt/volume/availSyscallDict.sav"

    riskData = dict()
    with open(sysRiskDictPath, 'rb') as f:  # syscallRiskDict
        riskData = pickle.load(f)
    riskList = riskData.keys()

    availData = dict()
    with open(availSyscallDictPath, 'rb') as f:  # availsyscallDict
        availData = pickle.load(f)
    availList = availData.keys()

    scoreDataPath = "/opt/volume/scoreData_"+sys.argv[1]+"_"+sys.argv[2]+"_"+today+".csv"
    with open(scoreDataPath, 'w') as f:
        f.write("System calls,Risk score,Ratio of each system call that passed LTP test (security container runtime/host),score\n")
        for syscall in availList :
            if availData[syscall] != 0 :
                avail = availData[syscall]
                if syscall in riskData:
                    risk = riskData[syscall]
                    f.write(syscall+','+str(risk)+','+str(avail)+','+str(risk*avail)+'\n')
                else:
                    f.write(syscall+','+'0'+','+str(avail)+',0'+'\n')
