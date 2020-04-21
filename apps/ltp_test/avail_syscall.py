from strace_parser.parser import get_parser
from typing import Any
#from lark import Token,Tree,Transformer
import subprocess
import os
import io
import pickle
from typing import Any

from lark import Transformer, Tree
import glob
import re

from functools import lru_cache
from lark import Lark


#from . import data
import subprocess

#@lru_cache(1)
def get_parser() -> Lark:
    grammar  = subprocess.check_output("cat grammar.txt",shell=True).decode().strip("\n")

    return Lark(grammar)

def convert(cls):
    def f(self, children):
        return cls(children[0])

    return f

def first_child():
    def f(self, children):
        return children[0]

    return f

class JsonTransformer(Transformer):
    def start(self, children):
        return children

    def line(self, children):
        timestamp, body = children
        body["timestamp"] = timestamp
        return body

    def syscall(self, children):
        name, args, result = children
        return {
            "type": "syscall",
            "name": name,
            "args": args,
            "result": result,
        }

    def args(self, children):
        return children

    def other(self, children):
        return {
            "type": "other",
            "value": str(children[0]),
        }

    def braced(self, children):
        return {
            "type": "braced",
            "value": children[0],
        }

    def bracketed(self, children):
        return {
            "type": "bracketed",
            "value": children[0],
        }

    def key_value(self, children):
        key, value = children
        return {
            "type": "key_value",
            "key": str(key),
            "value": value,
        }

    def alert_body(self, children):
        return {
            "type": "alert",
            "result": str(children[0]),
        }

    def function_like(self, children):
        name, args = children
        return {
            "type": "function",
            "name": str(name),
            "args": args,
        }

    def sigset(self, children):
        return {
            "type": "sigset",
            "negated": children[0].type == "NEGATED",
            "args": [str(c) for c in children[1:]],
        }

    key = convert(str)

    body = first_child()

    name = convert(str)

    result = convert(str)

    timestamp = convert(float)

    value = first_child()

def to_json(tree: Tree) -> Any:
    return JsonTransformer().transform(tree)

def straceFileCleansing(fileList, saveFilePath):
    template = "[0-9]+\.[0-9]+ ([a-zA-Z0-9_]+\(.*\)) = .*"
    compiled = re.compile(template)
    saveFile = open(saveFilePath,"w")
    for straceFilePath in fileList:
        with open(straceFilePath) as straceFile:
            for straceLine in straceFile.readlines():
                retMatch = compiled.match(straceLine)
                if retMatch != None:
                    syscallStr = retMatch.group(1)
                    cleanedSyscall = re.sub("\".+\"","",syscallStr).replace(", ",",").replace(","," ").replace("...","").replace("  ","")
                    saveFile.write(cleanedSyscall+"\n")

    saveFile.close()
    
    sortedFilePath  = saveFilePath +".sort"
    cmd = "cat "+saveFilePath+" | sort -u > " + sortedFilePath
    os.system(cmd)
    
    return sortedFilePath

def MakeSyscallDict(syscallFilePath):
    template = "([a-zA-Z0-9_]+)(\(.*\))"
    compiled = re.compile(template)
    syscallDict = dict()
    with open(syscallFilePath) as syscallFile:
        for line in syscallFile.readlines():
            retMatch = compiled.match(line.strip("\n"))
            if retMatch != None:
                syscallName = retMatch.group(1)
                parameter   = retMatch.group(2)
                if syscallDict.get(syscallName) == None:
                    syscallDict[syscallName] = list()
                syscallDict[syscallName].append(parameter)

    return syscallDict

def MakeAvailSyscallDict(hostSyscallDict, containerSyscallDict):
    availSyscallDict  = dict()
    syscalls = list(containerSyscallDict.keys())
    for syscallName in syscalls:
        availSyscallDict[syscallName] = len(hostSyscallDict)/len(containerSyscallDict)
    
    return availSyscallDict
def SaveDict(targetDict,path):
    with open(path,"wb") as f:
        pickle.dump(targetDict, f)

if __name__ == "__main__":
    hostFileList = glob.glob("/opt/volume/host/*")
    containerFileList = glob.glob("/opt/volume/container/*")

    cleanedHostFilePath = open("/opt/volume/cleaned_host_trace.txt","w")
    cleanedContainerFilePath = open("/opt/volume/cleaned_container_trace.txt","w")

    hostSyscallFilePath = straceFileCleansing(hostFileList, cleanedHostFilePath)
    containerSyscallFilePath = straceFileCleansing(containerList, cleanedContainerFilePath)
    
    hostSyscallDict = MakeSyscallDict(hostSyscallFilePath)
    containerSyscallDict = MakeSyscallDict(containerSyscallFilePath)
    
    availSyscallDict = MakeAvailSyscallDict(hostSyscallDict, containerSyscallDict)
    
    availSyscallSavePath = "/opt/volume/availSyscallDict.sav"
    SaveDict(availSyscallDict, availSyscallSavePath)
    
