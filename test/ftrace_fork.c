#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>

int main()
{
    int parent,pid,i;
    parent = getpid();
    printf("parent pid : %d\n",parent);
    
    sleep(10);   
    for (i=0;i<5;i++)
    {
        pid = fork();
        if(pid ==0)
            printf("child pid : %d\n",getpid());
    }
    sleep(15);
}
