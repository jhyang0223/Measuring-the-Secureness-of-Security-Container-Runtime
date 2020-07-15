from pyparsing import Word, alphas, nums, White, LineStart,alphanums,SkipTo,Keyword,Optional,Forward,Literal,delimitedList, cStyleComment,Group,QuotedString,nestedExpr
import sys

text = '''
// $ echo pikachu|sudo tee pokeball;ls -l pokeball;gcc -pthread pokemon.c -o d;./d pokeball miltank;cat pokeball
#include <fcntl.h>                        //// pikachu
#include <pthread.h>                      //// -rw-r--r-- 1 root root 8 Apr 4 12:34 pokeball
#include <string.h>                       //// pokeball
#include <stdio.h>                        ////    (___)
#include <stdint.h>                       ////    (o o)_____/
#include <sys/mman.h>                     ////     @@ `     \
#include <sys/types.h>                    ////      \ ____, /miltank
#include <sys/stat.h>                     ////      //    //
#include <sys/wait.h>                     ////     ^^    ^^
#include <sys/ptrace.h>                   //// mmap bc757000
#include <unistd.h>                       //// madvise 0
////////////////////////////////////////////// ptrace 0
////////////////////////////////////////////// miltank
//////////////////////////////////////////////
int f                                      ;// file descriptor
void *map                                  ;// memory map
pid_t pid                                  ;// process id
pthread_t pth                              ;// thread
struct stat st                             ;// file info
//////////////////////////////////////////////
void *madviseThread(void *arg)             // madvise thread
{  int i,c=0                                ;// counters
  for(i=0;i<200000000;i++)//////////////////// loop to 2*10**8
    c+=madvise(map,100,MADV_DONTNEED)      ;// race condition
  printf("madvise %d\n\n",c)               ;// sum of errors
'''

textt = '  printf({1,"asdb",3})               ;// sum of errors'


readFile = open("test.c","r")
readStr = readFile.read()
cFunction = Word(alphanums+"_")+ "(" + \
 Group( Optional(delimitedList(Word(alphanums+"_"+"="+"*"+" "+"["+"]")|QuotedString('"',multiline=True,escChar="\n")|nestedExpr(opener="{",closer="}"))) ) + ")" +";"
cFunction.ignore( cStyleComment )

cFuncDef = Word(alphanums+"_")+ "(" + \
 Group( Optional(delimitedList(Word(alphanums+"_"+"="+"*"+" "+"["+"]")|QuotedString('"',multiline=True,escChar="\n")|nestedExpr(opener="{",closer="}"))) ) + ")"+"{"
cFuncDef.ignore(cStyleComment)

for funcName in cFunction.searchString(readStr):
    print(funcName)

print("\n\nfunction definition\n\n")
for funcName in cFuncDef.searchString(readStr):
    print(funcName)
