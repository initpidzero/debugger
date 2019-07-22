#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

void handle(int sig)
{
        if(sig == SIGSEGV)
                printf("SIGSEGV recieved\n");
        exit(1);
}

static void bad_thing(void)
{
        char *bad_pointer = NULL;
        *bad_pointer = 0;
}

int main (void)
{
        unsigned long i;
        pid_t pid = getpid();

        struct sigaction act;
        act.sa_handler = handle;
        sigaction(SIGSEGV, &act, 0);

        for(i = 0; i < 44900; i++ )
        {
                printf("%d\n",pid);
                if(i == 0)
                        getchar();
        }
        bad_thing();
        return 0;
}
