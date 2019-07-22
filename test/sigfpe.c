#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

void handle(int sig)
{
        if(sig == SIGFPE)
                printf("SIGFPE recieved\n");
            exit(1);
}

static void bad_thing(void)
{
        int j = 0;
        int i = 9/j;
        printf("%d\n", i);
}

int main (void)
{
        unsigned long i = 0;
        pid_t pid = getpid();
        struct sigaction act;
        act.sa_handler = handle;
        sigaction(SIGFPE, &act, 0);

        for(; i < 44900; i++ )
        {
                printf("%d\n",pid);
                //        if(i == 0)
                //          getchar();
        }
        bad_thing();
        return 0;
}
