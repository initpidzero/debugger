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
    p_print,
    p_read,
    p_quit,
};

char commands[][8] = { "attach",
    "detach",
    "write",
    "print",
    "read",
    "quit"
};

char errors[][56] = { "Error: incorrect pid\n",
    "Error: unrecognised command\n",
    "Error: Invalid arguments\n",
    "Error: Attach failed\n",
    "Error: Detach failed\n",
    "Error: Fatal sycall failed\n",
};

static int print_regs(pid_t pid)
{
    char byte[256];

    struct user_regs_struct regs;
    int status = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if(status == -1)
        return -1;
    sprintf(byte, "%llx\n", regs.rip);
    write(STDOUT_FILENO, byte, strlen(byte) + 1);

    return 0;
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

static int pdetach(pid_t pid)
{
    int status = ptrace(PTRACE_DETACH, pid, 0 ,0);
    if(status == -1)
        return -1;

    char *p = "Process detached\n";
    write(STDOUT_FILENO, p, strlen(p) + 1);
    return 0;
}

static int peek(char *buf, pid_t pid)
{
    uintptr_t addr;
    char *data;
    char byte[buf_size];
    int i = 0;
    int total_words;
    union a {
        long word;
        char byte[8];
    };
    size_t len = 0;
    char * temp = buf + strlen(commands[p_read]) + 1;
    unsigned long  a  = strtoul(temp, &data, 16);
    addr = (intptr_t)a;
    if( a == 0 || errno != 0)
        return -1;
    temp = NULL;
    len = strtoul(data, &temp, 10);
    if( len == 0 || errno != 0)
        return -1;

    char output[len + 1];

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
        load.word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * 8), NULL);
        memcpy(output + i *8, load.byte, n);
    }
    output[len] = '\0';
    write(STDOUT_FILENO, output, strlen(output) + 1);

    return 0;
}

static int poke(char *buf, pid_t pid)
{
    intptr_t addr;
    char *data;
    char byte[buf_size];
    int i = 0;
    union a {
        long word;
        char byte[8];
    };
    int total_words;
    char * temp = buf + strlen(commands[p_write]) + 1;
    unsigned long  a  = strtoul(temp, &data, 16);
    addr = (intptr_t)a;
    if( a == 0 || errno != 0)
        return -1;
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
    //    printf("%s\n", load.byte);
        ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i * 8), load.word);
    }
    return 0;
}

static pid_t extract_pid(char *buf)
{
    pid_t pid;
    char * temp = buf + strlen(commands[p_attach])+ 1;
    pid = strtoul(temp, NULL, 10);
    return pid;
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
                    write(STDOUT_FILENO, errors[5], strlen(errors[0]) + 1);
        com = command_to_execute(buf);

        switch(com) {
            case p_attach:
                tracee_pid = extract_pid(buf);
                if(tracee_pid == 0)
                    write(STDOUT_FILENO, errors[0], strlen(errors[0]) + 1);
                else
                {
                    if(pattach(tracee_pid) == -1)
                        write(STDOUT_FILENO, errors[3], strlen(errors[3]) + 1);
                }
                break;

            case p_detach:
                if(pdetach(tracee_pid) == -1)
                    write(STDOUT_FILENO, errors[4], strlen(errors[4]) + 1);
                break;

            case p_write:
                if(poke(buf, tracee_pid) == -1)
                    write(STDOUT_FILENO, errors[2], strlen(errors[2]) + 1);
                break;

            case p_read:
                if(peek(buf, tracee_pid) == -1)
                    write(STDOUT_FILENO, errors[2], strlen(errors[2]) + 1);
                break;

            case p_print:
                if(print_regs(tracee_pid) == -1)
                    write(STDOUT_FILENO, errors[2], strlen(errors[2]) + 1);
                break;

            case p_quit:
                exit = 0;
                break;

            default:
                    write(STDOUT_FILENO, errors[1], strlen(errors[1]) + 1);
                /* do nothing */
                break;
        }
    }

    return 0;
}
