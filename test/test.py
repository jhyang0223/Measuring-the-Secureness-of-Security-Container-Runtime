from functools import lru_cache
from lark import Lark


#from . import data
import subprocess

#@lru_cache(1)
def get_parser() -> Lark:
    grammar  = subprocess.check_output("cat grammar.txt",shell=True).decode().strip("\n")
    
    return Lark(grammar)


print(get_parser().parse("1189.748113 wait4(14494, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 144\n"))
