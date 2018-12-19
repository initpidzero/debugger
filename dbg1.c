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

#define WORD 8

int buf_size = 256;

enum data_type {
    e_string,
    e_long
};

enum
{
    p_help,
    p_attach,
    p_detach,
    p_write,
    p_read,
    p_regs,
    p_step,
    p_cont,
    p_break,
    p_delete,
    p_quit
};

char commands[][9] = {
    "help",
    "attach",
    "detach",
    "write",
    "read",
    "regs",
    "step",
    "continue",
    "break",
    "delete",
    "quit"
};

char sregs[][8]  = {
"rax ",
"rbx",
"rcx",
"rdx",
"rsi",
"rdi",
"rbp",
"rsp",
"r8",
"r9",
"r10",
"r11",
"r12",
"r13",
"r14",
"r15",
"rip",
"eflags",
"cs",
"ss",
"ds",
"es",
"fs",
"gs"
};

struct bp
{
    uintptr_t addr;
    unsigned long word;
    int set;
};

static struct bp bp;

char errors[][128] = {
    "Error: Incorrect pid\n",
    "Error: Unrecognised command. Type help to see supported commands\n",
    "Error: Invalid arguments\n",
    "Error: Attach failed\n",
    "Error: Detach failed\n",
    "Error: Fatal sycall failed\n",
    "Error: Pid Not matching\n",
    "Error: Write failed\n",
    "Error: Read failed\n",
    "Error: Step failed\n",
    "Error: Continue failed\n",
};

static int print_str(char *temp)
{
    char buf[128];
    sprintf(buf, "%s\n", temp);
    write(STDOUT_FILENO, buf, strlen(buf) + 1);
}

static int print_error(int num)
{
    write(STDOUT_FILENO, errors[num], strlen(errors[num]) + 1);
}

static int command_to_execute(char *token)
{
    int i;
    for(i = 0; i < p_quit + 1; i++) {
        if(strncmp(commands[i], token, strlen(commands[i]))==0)
            return i;
    }
    return -1;
}

static char *tokenise(char *buf)
{
    return strtok(buf, " ");
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
    char *temp = strtok(NULL, " \n");
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

static int pwait(pid_t pid)
{
    int wstatus;
    int options = 0;
    int sig = 0;

    waitpid(pid, &wstatus, options);
    if (WIFEXITED(wstatus))
    {
        printf("exited, status=%d\n", WEXITSTATUS(wstatus));
    }
    else if (WIFSIGNALED(wstatus))
    {
        printf("killed by signal %d\n", WTERMSIG(wstatus));
    }
    else if (WIFSTOPPED(wstatus))
    {
        sig = WSTOPSIG(wstatus);
        printf("stopped by signal %d\n", sig);
    }
    else if (WIFCONTINUED(wstatus))
    {
        printf("continued\n");
    }

    return sig;
}

static int cont(pid_t pid)
{
    int status = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if(status == -1)
        return -1;
}

static int step(pid_t pid)
{
    int status = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if(status == -1)
        return -1;
}

static int set_regs(struct user_regs_struct *regs, pid_t pid)
{

    int status = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if(status == -1)
        return -1;
}

static int print_regs(struct user_regs_struct *regs, char *reg)
{
    if(strcmp (reg, "rax" ) == 0)
    {
        printf("rax = %llx\n", regs->rax);
    }
    if(strcmp (reg, "rbx" ) == 0)
    {
        printf("rbx = %llx\n", regs->rbx);
    }
    if(strcmp (reg, "rcx" ) == 0)
    {
        printf("rcx = %llx\n", regs->rcx);
    }
    if(strcmp (reg, "rdx" ) == 0)
    {
        printf("rdx = %llx\n", regs->rdx);
    }
    if(strcmp (reg, "rsi" ) == 0)
    {
        printf("rsi = %llx\n", regs->rsi);
    }
    if(strcmp (reg, "rdi" ) == 0)
    {
        printf("rdi = %llx\n", regs->rdi);
    }
    if(strcmp (reg, "rbp" ) == 0)
    {
        printf("rpb = %llx\n", regs->rbp);
    }
    if(strcmp (reg, "rsp" ) == 0)
    {
        printf("rsp = %llx\n", regs->rsp);
    }
    if(strcmp (reg, "r8" ) == 0)
    {
        printf("r8 = %llx\n", regs->r8);
    }
    if(strcmp (reg, "r9" ) == 0)
    {
        printf("r9 = %llx\n", regs->r9);
    }
    if(strcmp (reg, "r10" ) == 0)
    {
        printf("r10 = %llx\n", regs->r10);
    }
    if(strcmp (reg, "r11" ) == 0)
    {
        printf("r11 = %llx\n", regs->r11);
    }
    if(strcmp (reg, "r12" ) == 0)
    {
        printf("r12 = %llx\n", regs->r12);
    }
    if(strcmp (reg, "r13" ) == 0)
    {
        printf("r13 = %llx\n", regs->r13);
    }
    if(strcmp (reg, "r14" ) == 0)
    {
        printf("r14 = %llx\n", regs->r14);
    }
    if(strcmp (reg, "r15" ) == 0)
    {
        printf("r15 = %llx\n", regs->r15);
    }
    if(strcmp (reg, "rip" ) == 0)
    {
        printf("rip = %llx\n", regs->rip);
    }
    if(strcmp (reg, "eflags" ) == 0)
    {
        printf("eflags = %llx\n", regs->eflags);
    }
    if(strcmp (reg, "cs" ) == 0)
    {
        printf("cs = %llx\n", regs->cs);
    }
    if(strcmp (reg, "ss" ) == 0)
    {
        printf("ss = %llx\n", regs->ss);
    }
    if(strcmp (reg, "ds" ) == 0)
    {
        printf("ds = %llx\n", regs->ds);
    }
    if(strcmp (reg, "es" ) == 0)
    {
        printf("es = %llx\n", regs->es);
    }
    if(strcmp (reg, "fs" ) == 0)
    {
        printf("fs = %llx\n", regs->fs);
    }
    if(strcmp (reg, "gs" ) == 0)
    {
        printf("fs = %llx\n", regs->fs);
    }
}

static int get_regs(struct user_regs_struct *regs, pid_t pid)
{

    int status = ptrace(PTRACE_GETREGS, pid, NULL, regs);
    if(status == -1)
        return -1;
}

static int regs(char *buf, pid_t pid)
{

    struct user_regs_struct regs;
    get_regs(&regs, pid);

    print_regs(&regs, "rip");
    print_regs(&regs, "rsp");
    print_regs(&regs, "rbp");

    return 0;
}

static int peek_long(uintptr_t addr, long *word, pid_t pid)
{
    *word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr,
                         NULL);
    if(*word == -1 && errno != 0)
    {
        print_error(7);
    }

    printf("%lx\n", *word);
}

static int peek(uintptr_t addr, int len, pid_t pid)
{
    char byte[buf_size];
    int i = 0;
    union a {
        long word;
        char byte[8];
    };
    int total_words;

    total_words = (len)/8;
    if((len % 8) != 0)
        total_words = total_words + 1;

    printf("%d %p\n",len, addr);
    union a load;

    for(i = 0; i < total_words; i++)
    {
        int n = len - 8 * i;
        if(n > 8)
            n = 8;
        bzero(&load,  sizeof(load));
        load.word  = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i * 8), NULL);
        memcpy(byte + i * 8, load.byte, n);

    }
    byte[len + 1] = '\0';
    write(STDOUT_FILENO, byte, strlen(byte) + 1);
    return 0;
}

static int p_peek(char *buf, pid_t pid)
{
    uintptr_t addr;
    unsigned long long a;
    unsigned long word;
    char *temp = strtok(NULL, " ");

    a = strtoul(temp, NULL, 16);
    if( a == 0 || errno != 0)
        return -1;

    addr = (uintptr_t)a;

    temp = strtok(NULL, " \n");
    int len = strtoul(temp, NULL, 10);
    return peek(addr, len, pid);
    //return peek_long(addr, &word, pid);
}

static int poke_long(uintptr_t addr, long word, pid_t pid)
{
    int status  = ptrace(PTRACE_POKEDATA, pid, (void *)addr,
                         word);
    if(status == -1 && errno != 0)
    {
        print_error(7);
    }
}

static int poke(uintptr_t addr, char *byte, pid_t pid)
{
    int i;
    union a {
        long word;
        char byte[8];
    };
    int total_words;
    int len = strlen(byte);

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
        int status  = ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i * 8),
                             load.word);
        if(status == -1 && errno != 0)
        {
            print_error(7);
            return 0;
        }

    }
    return 0;
}

static int p_poke(char *buf, pid_t pid)
{

    uintptr_t addr;
    char *temp = NULL;
    char byte[buf_size];
    int i = 0;
    unsigned long long a;

    temp = strtok(NULL, " ");
    a  = strtoull(temp, NULL, 16);
    if( a == 0 || errno != 0)
        return -1;

    addr = (uintptr_t)a;
    temp = strtok(NULL, " \n");
    strcpy(byte, temp);
    i = strlen(byte);
    byte[i] = '\n';
    byte[i + 1] = '\0';
    //return poke(addr, byte, pid);
    return poke_long(addr, 0xffeeaa, pid);
}

/* remove break  point */
static int rm_bp(struct bp *bp, pid_t pid)
{
    struct user_regs_struct regs;

    get_regs(&regs, pid);
    poke_long(bp->addr, bp->word, pid);
    regs.rip = bp->addr;
    set_regs(&regs, pid);
    bp->set = 0;
}

static int cont_bp(pid_t pid)
{
    cont(pid);
    if(pwait(pid) == SIGTRAP)
        print_str("Breakpoint hit");
}

static int set_bp(struct bp *bp, pid_t pid)
{
    unsigned long trap;

    /* read data at addr */
    peek_long(bp->addr, &bp->word, pid);

    trap = bp->word & ~0xff;
    trap = trap | 0xcc;
    poke_long(bp->addr, trap, pid);
    bp->set = 1;

    // so first let it hit the breakpoint
    // write the correct data back into its memory
    //
    //get_regs(&regs, pid);
    //step(pid);
}

static int delete(pid_t pid)
{

}

static int breakpoint(char *buf, pid_t pid)
{
    char *temp = strtok(NULL, " ");

    bp.addr = (uintptr_t)strtoul(temp, NULL, 16);
    if( bp.addr == 0 || errno != 0)
        return -1;
    set_bp(&bp, pid);
    cont_bp(pid);
    rm_bp(&bp, pid);
}

void help()
{
    char *help_str = "Commands supported\n"
        "help:      This command\n"
        "attach:    Attach to (pid)\n"
        "detach:    Detach \n"
        "write:     Write (value) to (addr)\n"
        "read:      Read from (addr) for (len) bytes\n"
        "regs:      Get regs value for optional [reg name]\n"
        "step:      Go forward one instruction\n"
        "continue:  Continue \n"
        "break:     Set break point at (addr)\n"
        "quit:      Exit from debugger\n" ;

    write(STDOUT_FILENO,help_str, strlen(help_str) + 1);
}

int main (int argc, char **argv)
{
    int exit = 1 ;
    char prompt[] = "(dbg):";
    char buf[buf_size];
    int com;
    int tracee_pid;
    char *token;

    /* at the beginning no break point was set */
    bp.set = 0;

    while(exit)
    {
        int bytes_read;
        write(STDOUT_FILENO, prompt, strlen(prompt) + 1);
        bytes_read = read(STDIN_FILENO, buf, buf_size);
        if(bytes_read == -1)
            print_error(6);
        token = tokenise(buf);
        com = command_to_execute(token);

        switch(com)
        {
            case p_help:
                help();
                break;

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
                if(p_poke(buf, tracee_pid) == -1)
                    print_error(2);
                break;

            case p_read:
                if(p_peek(buf, tracee_pid) == -1)
                    print_error(2);
                break;

            case p_regs:
                if(regs(buf, tracee_pid) == -1)
                    print_error(2);
                break;

            case p_cont:
                if(cont(tracee_pid) == -1)
                    print_error(10);
                break;

            case p_step:
                if(step(tracee_pid) == -1)
                    print_error(9);
                break;

            case p_break:
                if(breakpoint(buf, tracee_pid) == -1)
                    print_error(2);
                break;

            case p_delete:
                if(delete(tracee_pid) == -1)
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
