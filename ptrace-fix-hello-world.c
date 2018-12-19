/* This program should be able to use basic ptrace functionality of 
 * attaching, detaching and writing to a process */

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

int buf_size = 256;

enum {
    p_attach,
    p_detach,
    p_write,
    p_quit
};

char commands[][8] = { "attach",
    "detach",
    "write",
    "quit"
};

char errors[][56] = { "Error: incorrect pid\n",
    "Error: unrecognised command\n",
    "Error: Invalid arguments\n",
    "Error: Attach failed\n",
    "Error: Detach failed\n",
    "Error: Fatal sycall failed\n",
    "Error: Pid Not matching\n",
    "Error: Write failed\n",
};

static int print_error(int num)
{
    write(STDOUT_FILENO, errors[num], strlen(errors[num]) + 1);
}

static int command_to_execute(char *buf)
{
    int i;
    int command;
    for(i = 0; i < p_quit + 1; i++) {
        if(strncmp(commands[i], buf, strlen(commands[i]))==0)
            return i;
    }
    return -1;
}

static int pattach(pid_t pid)
{
    int status = ptrace(PTRACE_ATTACH, pid, 0 ,0);
    if(status == -1)
        return -1;

    char *p = "Process attached\n";
    write(STDOUT_FILENO, p, strlen(p) + 1);

    return 0;
}

static pid_t extract_pid(char *buf, int com)
{
    pid_t pid;
    char * temp = buf + strlen(commands[com])+ 1;
    pid = strtoul(temp, NULL, 10);
    return pid;
}

static int pdetach(pid_t pid)
{
    int status = ptrace(PTRACE_DETACH, pid, 0 ,0);
    if(status == -1)
        return -1;

    char *p = "Process detached\n";
    write(STDOUT_FILENO, p, strlen(p) + 1);
    return 0;
}

static int poke(char *buf, pid_t pid)
{
    intptr_t addr;
    char *temp = NULL;
    char byte[buf_size];
    int i = 0;
    union a {
        long word;
        char byte[8];
    };
    int total_words;
    unsigned long long a;
    char *data = buf + strlen(commands[p_write]) + 1;
    pid_t tracee_pid = strtoul(data, &temp, 10);
    //printf("%d\n", tracee_pid);
    if( tracee_pid == 0 || errno != 0)
        return -1;
    data = NULL;

    a  = strtoull(temp + 1, &data, 16);
    //printf("%llx\n", a);
    if( a == 0 || errno != 0)
        return -1;
    if(tracee_pid != pid)
            print_error(6);
    addr = (intptr_t)a;
    temp = NULL;
    for(temp = data + 1; *temp != '\n'; temp++)
    {
        byte[i] = *temp;
        i++;
    }
    byte[i] = '\n';
    byte[i + 1] = '\0';
    int len = i + 1;

    total_words = (len)/8;
    if((len % 8) != 0)
        total_words = total_words + 1;

    union a load;

    for(i = 0; i < total_words; i++)
    {
        int n = len - 8 * i;
        if(n > 8)
            n = 8;
        bzero(&load,  sizeof(load));
        memcpy(load.byte, byte + i * 8, n);
        int status  = ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i * 8), load.word);
        if(status == -1 && errno != 0) {
            print_error(7);
            return 0;
        }

    }
    return 0;
}


int main (int argc, char **argv)
{
    int exit = 1 ;
    char prompt[] = "(ptracer):";
    char buf[buf_size];
    int com;
    int tracee_pid;

    while(exit)
    {
        int bytes_read;
        write(STDOUT_FILENO, prompt, strlen(prompt) + 1);
        bytes_read = read(STDIN_FILENO, buf, buf_size);
        if(bytes_read == -1)
            print_error(6);
        com = command_to_execute(buf);

        switch(com) {
            case p_attach:
                tracee_pid = extract_pid(buf, com);
                if(tracee_pid == 0)
                    print_error(0);
                else
                {
                    if(pattach(tracee_pid) == -1)
                        print_error(3);
                }
                break;

            case p_detach:
                if(pdetach(tracee_pid) == -1)
                    print_error(4);
                break;

            case p_write:
                if(poke(buf, tracee_pid) == -1)
                    print_error(2);
                break;

            case p_quit:
                exit = 0;
                break;
            default:
                    print_error(1);
                /* do nothing */
                break;
        }
    }

    return 0;
}
