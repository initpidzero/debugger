/* This program should be able to use basic ptrace functionality of
 * attaching, detaching and writing to a process */

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>

int buf_size = 256;

/* This is debuggee pid */
int main (int argc, char **argv)
{
    int exit = 1; /* The value is changed to zero when user calls quit command */
    char prompt[] = "(dbg):";
    char buf[buf_size];

    /* no debuggee at the beginning either */
//    tracee_pid = 0;
    /* at the beginning no break point was set */
  //  bp.set = 0;
    while(exit)
    {
        ssize_t bytes_read;

        if(write(STDOUT_FILENO, prompt, strlen(prompt) + 1) == -1)
            fprintf(stderr, "write failed : %s\n", strerror(errno));

        bzero(buf, buf_size);
        bytes_read = read(STDIN_FILENO, buf, buf_size);
        if(bytes_read == -1)
            fprintf(stderr, "read failed : %s\n", strerror(errno));
        assert(bytes_read > 0);

        dbg(&exit, buf);
    }
    return 0;
}
