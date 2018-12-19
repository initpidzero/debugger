#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

void handle(int sig)
{
    if(sig == SIGALRM)
        printf("SIGALRM recieved\n");
    exit(1);
}

static void
bad_thing(void)
{
    alarm(1);
}

int main (void)
{
    unsigned long i = 0;
    pid_t pid = getpid();
    char hello[] = "hello world";
    struct sigaction act;
    act.sa_handler = handle;
    sigaction(SIGALRM, &act, 0);

    //for(; i < 44900; i++ )
    //{
        printf("%d\n",pid);
       // if(i == 0)
         //   getchar();
    //}
    bad_thing();
    sleep(1);
    return 0;
}
