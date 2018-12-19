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
static int tracee_pid =  0;

/* each command is given an index, which makes it easier to
 * maintain switch case for various commands */
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

/* corresponsing command string for each command */
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

/* string for register names */
char sregs[][8]  = {
"rax",
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

/* this structure keeps track of breakpoint related data */
struct bp
{
    uintptr_t addr; /* address where break point is set */
    unsigned long word; /* content at breakpoint address */
    unsigned long trap; /* replacement for trap instruction on address */
    int set; /* 0 = bp is not set. 1 = bp is set.
              * 2 = breakpoint was hit and needs to be set again */
};

/* we are only supporting one break point at this moment */
static struct bp bp;

/* this function takes token string as argument and
 * converts it into command index */
static int command_to_execute(char *token)
{
    int i;
    for(i = 0; i < p_quit + 1; i++) {
        if(strncmp(commands[i], token, strlen(commands[i]))==0)
            return i;
    }
    return -1;
}

/* tokenise first string from buf until a blank space is found */
static char *tokenise(char *buf)
{
    return strtok(buf, " ");
}


/* This function uses waitpid on pid to check status of debuggee process,
 * when it exits or recieves a signal.
 * return : The signal value recieved from debuggee */
static int pwait_step(pid_t pid)
{
    int wstatus;
    int options = WNOHANG;
    int sig = 0;

    waitpid(pid, &wstatus, options);
    if (WIFEXITED(wstatus))
    {
        printf("Debuggee exits with status %d\n", WEXITSTATUS(wstatus));
        /* debuggee has exited, reset tracee_pid */
        tracee_pid = 0;
    }
    else if (WIFSIGNALED(wstatus))
    {
        sig = WTERMSIG(wstatus);
        printf("Debuggee killed by signal %d\n", sig);
        /* debuggee was killed, reset tracee_pid */
        tracee_pid = 0;
    }
    else if (WIFSTOPPED(wstatus))
    {
        sig = WSTOPSIG(wstatus);
        printf("Debuggee stopped by signal %d\n", sig);
    }
    else if (WIFCONTINUED(wstatus))
    {
        printf("Debuggee continues\n");
    }

    return sig;
}
/* This function uses waitpid on pid to check status of debuggee process,
 * when it exits or recieves a signal.
 * return : The signal value recieved from debuggee */
static int pwait(pid_t pid)
{
    int wstatus;
    int options = 0;
    int sig = 0;

    waitpid(pid, &wstatus, options);
    if (WIFEXITED(wstatus))
    {
        printf("Debuggee exits with status %d\n", WEXITSTATUS(wstatus));
        /* debuggee has exited, reset tracee_pid */
        tracee_pid = 0;
    }
    else if (WIFSIGNALED(wstatus))
    {
        sig = WTERMSIG(wstatus);
        printf("Debuggee killed by signal %d\n", sig);
        /* debuggee was killed, reset tracee_pid */
        tracee_pid = 0;
    }
    else if (WIFSTOPPED(wstatus))
    {
        sig = WSTOPSIG(wstatus);
        printf("Debuggee stopped by signal %d\n", sig);
    }
    else if (WIFCONTINUED(wstatus))
    {
        printf("Debuggee continues\n");
    }

    return sig;
}

/* This function calls ptrace with PTRACE_CONT */
static int cont(pid_t pid)
{
    int status = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if(status == -1)
        return -1;
}

/* This function gets user register data in regs for pid */
static int set_regs(struct user_regs_struct *regs, pid_t pid)
{

    int status = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if(status == -1)
        return -1;
}

/* This function will print contents of registers in regs data structure.
 * reg: Register for which value needs to be printed */
static void print_regs(struct user_regs_struct *regs, char *reg)
{
    if(strcmp(reg, "rax" ) == 0)
    {
        printf("rax 	0x%llx\n", regs->rax);
    }
    else if(strcmp(reg, "rbx" ) == 0)
    {
        printf("rbx 	0x%llx\n", regs->rbx);
    }
    else if(strcmp(reg, "rcx" ) == 0)
    {
        printf("rcx 	0x%llx\n", regs->rcx);
    }
    else if(strcmp(reg, "rdx" ) == 0)
    {
        printf("rdx 	0x%llx\n", regs->rdx);
    }
    else if(strcmp(reg, "rsi" ) == 0)
    {
        printf("rsi 	0x%llx\n", regs->rsi);
    }
    else if(strcmp(reg, "rdi" ) == 0)
    {
        printf("rdi 	0x%llx\n", regs->rdi);
    }
    else if(strcmp(reg, "rbp" ) == 0)
    {
        printf("rpb 	0x%llx\n", regs->rbp);
    }
    else if(strcmp(reg, "rsp" ) == 0)
    {
        printf("rsp 	0x%llx\n", regs->rsp);
    }
    else if(strcmp(reg, "r8" ) == 0)
    {
        printf("r8 	0x%llx\n", regs->r8);
    }
    else if(strcmp(reg, "r9" ) == 0)
    {
        printf("r9 	0x%llx\n", regs->r9);
    }
    else if(strcmp(reg, "r10" ) == 0)
    {
        printf("r10 	0x%llx\n", regs->r10);
    }
    else if(strcmp(reg, "r11" ) == 0)
    {
        printf("r11 	0x%llx\n", regs->r11);
    }
    else if(strcmp(reg, "r12" ) == 0)
    {
        printf("r12 	0x%llx\n", regs->r12);
    }
    else if(strcmp(reg, "r13" ) == 0)
    {
        printf("r13 	0x%llx\n", regs->r13);
    }
    else if(strcmp(reg, "r14" ) == 0)
    {
        printf("r14 	0x%llx\n", regs->r14);
    }
    else if(strcmp(reg, "r15" ) == 0)
    {
        printf("r15 	0x%llx\n", regs->r15);
    }
    else if(strcmp(reg, "rip" ) == 0)
    {
        printf("rip 	0x%llx\n", regs->rip);
    }
    else if(strcmp(reg, "eflags" ) == 0)
    {
        printf("eflags 	0x%llx\n", regs->eflags);
    }
    else if(strcmp(reg, "cs" ) == 0)
    {
        printf("cs 	0x%llx\n", regs->cs);
    }
    else if(strcmp(reg, "ss" ) == 0)
    {
        printf("ss 	0x%llx\n", regs->ss);
    }
    else if(strcmp(reg, "ds" ) == 0)
    {
        printf("ds 	0x%llx\n", regs->ds);
    }
    else if(strcmp(reg, "es" ) == 0)
    {
        printf("es 	0x%llx\n", regs->es);
    }
    else if(strcmp(reg, "fs" ) == 0)
    {
        printf("fs 	0x%llx\n", regs->fs);
    }
    else if(strcmp(reg, "gs" ) == 0)
    {
        printf("fs 	0x%llx\n", regs->fs);
    }
    else
    {
        printf("No such register %s\n", reg);
    }
}

/* This function gets value of user registers in regs data structure
 * for debuggee with process id pid */
static int get_regs(struct user_regs_struct *regs, pid_t pid)
{
    int status = ptrace(PTRACE_GETREGS, pid, NULL, regs);
    if(status == -1)
        return -1;
}

/* This function prints entire set of user registers one by one */
void print_all_regs( struct user_regs_struct *regs)
{
    int total_regs = sizeof(sregs)/sizeof(sregs[0]);
    int i = 0;

    for(i = 0; i < total_regs; i++)
        print_regs(regs, sregs[i]);
}

/* This function will obtain value for registers using get_regs() function
 * and print them.
 * regs: register whose value needs to obtained
 * if regs is NULL, value for all registers are printed */
static int regs_value(pid_t pid, char *reg)
{
    struct user_regs_struct regs;
    if(get_regs(&regs, pid) == -1)
        return -1;

    if(strcmp(reg, "all") == 0)
       print_all_regs(&regs);
    else
        print_regs(&regs, reg);

    return 0;
}

/* This function is called when user enters regs command.
 * It parses arguments for regs command to find which register's
 * value user want to see */
static int regs(char *buf, pid_t pid)
{
    char *temp = strtok(NULL, "\n");

    if(temp == NULL)
        temp = "all";

    /* call regs_value to actually obtain regs data
     * and print register values */
    return regs_value(pid, temp);

}

/* This function read data from address
 * addr: address to which data should be read from
 * word: content at the address addr */
static int peek_long(uintptr_t addr, unsigned long *word, pid_t pid)
{
    *word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr,
                         NULL);
    if(*word == -1 && errno != 0)
    {
        fprintf(stderr, "peekdata failed with %s\n", strerror(errno));
        return -1;
    }

    printf("%lx\n", *word);
    return 0;
}

/* This function is called when user enters read command.
 * It parses arguments for read command to find which address
 * value user want read */
static int p_peek(char *buf, pid_t pid)
{
    uintptr_t addr = 0;
    unsigned long word = 0;
    char *temp = strtok(NULL, " \n");
    if(temp == NULL)
        return -1;

    addr = (uintptr_t)strtoul(temp, NULL, 16);
    if( addr == 0 || errno != 0)
        return -1;

    return peek_long(addr, &word, pid);
}

/* This function writes data to an address
 * addr: address to which data should be written
 * word: content to be written to address addr */
static int poke_long(uintptr_t addr, unsigned long word, pid_t pid)
{
    //printf("addr data = %p %lx\n", addr, word);
    int status  = ptrace(PTRACE_POKEDATA, pid, (void *)addr,
                         word);
    if(status == -1 && errno != 0)
    {
        fprintf(stderr, "peekdata failed with %s\n", strerror(errno));
    }
    return status;
}

/* This function is called when user enters write command.
 * It parses arguments for write command to find which address
 * value user want to write at and what content user want to write */
static int p_poke(char *buf, pid_t pid)
{
    uintptr_t addr;
    unsigned long word;

    char *temp = strtok(NULL, " ");
    if(temp == NULL)
        return -1;

    addr  = (uintptr_t)strtoul(temp, NULL, 16);
    if(addr == 0 || errno != 0)
        return -1;

    temp = strtok(NULL, " \n");
    if(temp == NULL)
        return -1;

    word = strtoul(temp, NULL, 16);
    if(word == 0 || errno != 0)
        return -1;

    return poke_long(addr, word, pid);
}

/* remove breakpoint  bp*/
/* Write the value at breakpoint addr back to 
 * what it was before breakpoint was set. */
static int rm_bp(struct bp *bp, pid_t pid)
{
    if(poke_long(bp->addr, bp->word, pid) == -1)
        return -1;
    bp->set = 0;
}

 /*This function restores the value which was overwritten 
  * at bp address. It also resets instruction pointer
  * back to bp address*/
static int unset_bp(struct bp *bp, pid_t pid)
{
    struct user_regs_struct regs;

    /* remove breakpoint */
    if(rm_bp(bp, pid) == -1)
        return -1;

    if(get_regs(&regs, pid) == -1)
        return -1;

    /* reset rip to previous value */
    regs.rip = bp->addr;

    return set_regs(&regs, pid);
}

/* This function overwrites value at breakpoint address with 
 * trap instruction */
static int add_bp(struct bp *bp, pid_t pid)
{
    if(poke_long(bp->addr, bp->trap, pid) == -1)
        return -1;

    bp->set = 1; /* this breakpoint is now set */
    return 0;
}

/* This function finds out the content at breakpoint address.
 * Create a suitable value for trap instruction
 * sets breakpoint */
static int set_bp(struct bp *bp, pid_t pid)
{
    /* read data at addr */
    if(peek_long(bp->addr, &bp->word, pid) == -1)
        return -1;
    /* overwrite last byte with trap instruction */
    bp->trap = (bp->word & ~0xff) | 0xcc;

    /* add breakpoint by overwriting content of bp->addr*/
    return add_bp(bp, pid);
}

/* This function is called when breakpoint is hit
 * but we have reset register values and breakpoint address
 * to before we recieved SIGTAP. This will put breakpoint back before we can
 * either step or continue */
static int resume_bp(pid_t pid)
{
    if(bp.set == 2)
       return add_bp(&bp, pid);

}

/* single step on each instruction */
static int step(pid_t pid)
{
    /* check if there was a breakpoint */
    if(resume_bp(pid) == -1)
        return -1;

    int status = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if(status == -1)
        return -1;
    if(pwait_step(pid) == SIGTRAP && bp.set == 1)
    {
        printf("Breakpoint hit at ");
    }

    return 0;
}

/* This function resumes execution flow when debuggee is stopped because
 * 1.Signal was recieved by debuggee
 * 2. breakpoint was hit
 * 3. User sent "continue" command */
static int cont_bp(pid_t pid)
{
    /* check if there was a pending breakpoint */
    if(resume_bp(pid) == -1)
    {
        printf("resume breakpoint failed\n");
        return -1;
    }

    /* call ptrace continue */
    if(cont(pid) == -1)
        return -1;

    /* wait for either a signal or exit from debuggee*/
    if(pwait(pid) == SIGTRAP && bp.set == 1)
    {
        printf("Breakpoint hit at ");
        regs_value(pid, "rip");
         /* we reset all values back to what they were before hitting breakpoint
         * so next time any command that runs should set the breakpoint back */
        if(unset_bp(&bp, pid) == -1)
        {
            printf("unset bp failed\n");
            return -1;
        }
        /* so if the flag is at 2, that means a breakpoint is now in pending
         * position. resume_bp() should be called from any place expecting
         * hitting a breakpoint */
        bp.set = 2;
    }

    return 0;
}

/* This function is called with user sends delete command
 * It removes the break point or tells user if there is no
 * breakpoints currently active */
static int delete(pid_t pid)
{
    if(bp.set == 1)
        return rm_bp(&bp, pid);
    else if(bp.set == 2)
        bp.set = 0;
    else
        printf("No breakpoint found\n");

    printf("Breakpoint Deleted\n");
    return 0;
}

/* This function is called with user sends breakpoint command
 * It obtains addr for break point
 * Checks if breakpoint at this address is active
 * sets breakpoint on user provided address */
static int breakpoint(char *buf, pid_t pid)
{
    uintptr_t addr = 0;
    char *temp = strtok(NULL, " ");
    if(temp == NULL)
        return -1;

    addr = (uintptr_t)strtoul(temp, NULL, 16);
    if(addr == 0 || errno != 0)
        return -1;

    if(bp.set == 1 && addr == bp.addr)
    {
        printf("Breakpoint already set on this address\n");
        return 0;
    }
    bp.addr = addr;
    return set_bp(&bp, pid);
}

/* prints help */
void help()
{
    char *help_str = "Commands supported\n"
        "help:      This command\n"
        "attach:    Attach to (pid)\n"
        "detach:    Detach \n"
        "write:     Write (value) to (addr)\n"
        "read:      Read from (addr) \n"
        "regs:      Get regs value for optional [reg name]\n"
        "step:      Go forward one instruction\n"
        "continue:  Continue \n"
        "break:     Set break point at (addr)\n"
        "quit:      Exit from debugger\n" ;

    printf("%s", help_str);
}

/* detach the debuggee */
static int pdetach(pid_t pid)
{
    /* remove breakpoint data before detaching */
    if(bp.set == 1)
    {
        if(rm_bp(&bp, pid) == - 1)
            return -1;
    }
    else if(bp.set == 2)
    {
        bp.set = 0;
    }

    int status = ptrace(PTRACE_DETACH, pid, 0 ,0);
    if(status == -1)
        return -1;

    printf("Process detached\n");
    return 0;
}

/* attach to the debuggee */
static int pattach(pid_t pid)
{
    int status = ptrace(PTRACE_ATTACH, pid, 0 ,0);
    if(status == -1)
        return -1;

    printf("Process attached\n");

    pwait(pid);

    return 0;
}

/* This function simply extracts pid from
 * user supplied attach command */
static pid_t extract_pid(char *buf, int com)
{
    pid_t pid;
    char *temp = strtok(NULL, " \n");
    if(temp == NULL)
        return -1;
    pid = strtoul(temp, NULL, 10);
    return pid;
}

int main (int argc, char **argv)
{
    int exit = 1; /* The value is changed to zero when user calls quit command */
    char prompt[] = "(dbg):";
    char buf[buf_size];
    int com;
    char *token;

    tracee_pid = 0;

    /* at the beginning no break point was set */
    bp.set = 0;

    while(exit)
    {
        int bytes_read;

        if(write(STDOUT_FILENO, prompt, strlen(prompt) + 1) == -1)
            fprintf(stderr, "write failed with %s\n", strerror(errno));

        bytes_read = read(STDIN_FILENO, buf, buf_size);
        assert(bytes_read > 0);
        if(bytes_read == -1)
            fprintf(stderr, "write failed with %s\n", strerror(errno));

        token = tokenise(buf);
        if(token == NULL)
            fprintf(stderr, "strtok failed with %s\n", strerror(errno));

        /* convert command into index */
        com = command_to_execute(token);
        switch(com)
        {
            case p_help:
                help();
                break;

            case p_attach:
                /* If tracee_pid is not valid, debuggee cannot be attached */
                tracee_pid = extract_pid(buf, com);
                if(tracee_pid == -1)
                {
                    fprintf(stderr, "No pid specified\n");
                    tracee_pid = 0;
                }
                else if(tracee_pid == 0)
                    fprintf(stderr, "unable to extract pid\n");
                else
                {
                    if(pattach(tracee_pid) == -1)
                        fprintf(stderr, "attach failed\n");
                }
                break;

            case p_detach:
                if(tracee_pid == 0)
                {
                    fprintf(stderr, "No debuggee found\n");
                    break;
                }
                if(pdetach(tracee_pid) == -1)
                        fprintf(stderr, "detach failed\n");
                else
                    tracee_pid = 0;
                break;

            case p_write:
                if(p_poke(buf, tracee_pid) == -1)
                    fprintf(stderr, "unable to write\n");
                break;

            case p_read:
                if(p_peek(buf, tracee_pid) == -1)
                    fprintf(stderr, "unable to read\n");
                break;

            case p_regs:
                if(regs(buf, tracee_pid) == -1)
                    fprintf(stderr, "unable to get register values\n");
                break;

            case p_cont:
                if(cont_bp(tracee_pid) == -1)
                    fprintf(stderr, "unable to continue\n");
                break;

            case p_step:
                if(step(tracee_pid) == -1)
                    fprintf(stderr, "unable to step\n");
                break;

            case p_break:
                if(breakpoint(buf, tracee_pid) == -1)
                    fprintf(stderr, "Breakpoint couldn't be set\n");
                break;

            case p_delete:
                if(delete(tracee_pid) == -1)
                    fprintf(stderr, "Cannot delete breakpoint \n");
                break;

            case p_quit:
                /* exit clean by detaching before quiting */
                if(tracee_pid != 0)
                    if(pdetach(tracee_pid) == -1)
                        fprintf(stderr ,"Coudn't detach before exit\n");
                exit = 0;
                break;

            default:
                fprintf(stderr, "Unrecognised command. \
                        Type help to see supported commands\n");
                break;
        }
    }

    return 0;
}
