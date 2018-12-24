/* This program should be able to use basic ptrace functionality of
 * attaching, detaching and writing to a process */

#define _XOPEN_SOURCE 500 /* for TRACE_* */

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
#include "dbg.h"
#include <strings.h>

int buf_size = 256;

/* This is debuggee pid */
static int tracee_pid =  0;

/* each command is given an index, which makes it easier to
 * maintain switch case for various commands */
enum
{
    p_help,
    p_run,
    p_attach,
    p_detach,
    p_write,
    p_read,
    p_regs,
    p_step,
    p_cont,
    p_break,
    p_delete,
    p_signal,
    p_bt,
    p_quit
};

/* corresponsing command string for each command */
char commands[][10] = {
    "help",
    "run",
    "attach",
    "detach",
    "write",
    "read",
    "regs",
    "step",
    "continue",
    "break",
    "delete",
    "signal",
    "backtrace",
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

/* Breakpoint data structure */
static struct bp bp;

/* last signal recieved and associated action */
struct sig_dis sig_dis;

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

/* remove signals from sig_dis data structure  */
static void rm_sig()
{
    sig_dis.sig = 0;
    sig_dis.set = 0;
}

/* reset sig_dis data structure to ignore signals*/
static void unset_sig()
{
    sig_dis.act = 0;
    rm_sig();
}

/* If a signal is recieved and our signal action is
 * pass, we add signal to data sig_dis structure */
static void add_sig(int sig)
{
    if(sig_dis.act == 1)
    {
        sig_dis.sig = sig;
        sig_dis.set = 1;
    }
}
/* get more information about SIGTRAP.
 * If this is TRAP_TRACE and TRAP_BRKPT
 * it is from debugee, else it is from user
 */

static int get_siginfo(pid_t pid)
{
    siginfo_t siginfo;
    ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
    //printf("%d\n",siginfo.si_signo);
    //printf("%d %d\n",siginfo.si_code, TRAP_BRKPT);
    if(siginfo.si_code == TRAP_BRKPT)
    {
        //printf("Break point\n");
        return 0;
    }
    if(siginfo.si_code == TRAP_TRACE)
    {
        //printf("Trace\n");
        return 0;
    }
    if(siginfo.si_code == SI_KERNEL)
    {
        //printf("Trace\n");
        return 0;
    }
    if(siginfo.si_code == SI_USER)
    {
        //printf("Trace\n");
        return siginfo.si_signo;
    }
    return siginfo.si_signo;
}

/* This function takes an appropriate action based on
 * signal action settings */
static void set_sig(int sig)
{
    switch(sig)
    {
        case 0:
            break;
        case SIGTRAP:
            /* need a check if this is from debugger or debuggee */
            if(get_siginfo(tracee_pid))
                add_sig(sig);
            break;
        case SIGINT:
            printf("Debuggee has received SIGINT\n");
            add_sig(sig);
            break;
        case SIGSTOP:
            break;
        case SIGFPE:
            printf("Debuggee has received SIGFPE\n");
            add_sig(sig);
            break;
        case SIGILL:
            printf("Debuggee has received SIGILL\n");
            add_sig(sig);
            break;
        case SIGALRM:
            printf("Debuggee has received SIGALRM\n");
            add_sig(sig);
            break;
        case SIGSEGV:
            printf("Debuggee has received SIGSEGV\n");
            add_sig(sig);
            break;
        default:
            add_sig(sig);
            break;
    }
}

/* This function uses waitpid on pid to check status of debuggee process,
 * when it exits or recieves a signal.
 * return : The signal value recieved from debuggee */
static int pwait(pid_t pid, int options)
{
    int wstatus;
    int sig = 0;

    waitpid(pid, &wstatus, options);
    if (WIFEXITED(wstatus))
    {
        printf("Debuggee exits with status %d\n", WEXITSTATUS(wstatus));
        /* debuggee has exited, reset tracee_pid */
        tracee_pid = 0;
    }
    else if(WIFSIGNALED(wstatus))
    {
        sig = WTERMSIG(wstatus);
        printf("Debuggee killed by signal %d\n", sig);
        /* debuggee was killed, reset tracee_pid */
        tracee_pid = 0;
    }
    else if(WIFSTOPPED(wstatus))
    {
        sig = WSTOPSIG(wstatus);
        set_sig(sig);
    }
    else if(WIFCONTINUED(wstatus))
    {
        printf("Debuggee continues\n");
    }

    return sig;
}

/* This function is ptrace detach*/
/* It also checks for any signals which needs to delivered */
static int detach(pid_t pid)
{
    int sig = 0;
    /* are there any pending signal */
    if(sig_dis.set == 1 && sig_dis.act == 1)
        sig = sig_dis.sig;
    int status = ptrace(PTRACE_DETACH, pid, 0 , sig);
    if(status == -1 && errno != 0)
    {
        fprintf(stderr, "detach failed : %s\n", strerror(errno));
        return -1;
    }

    /* we have sent the pending signal, remove them from queue */
    if(sig_dis.set == 1 && sig_dis.act == 1)
        rm_sig();
    return 0;
}

/* reset all entries in signal and breakpoint data structure */
static void clear_ds()
{
    bzero(&bp,sizeof(bp));
    rm_sig();
}

/* This function deals with pending SIGSEGV */
static int segv_handle(pid_t pid)
{
    detach(pid);
    clear_ds();
    tracee_pid = 0;
    return 0;
}

/* This function calls ptrace with PTRACE_CONT */
static int cont(pid_t pid)
{
    int sig = 0;
    /* check for pending signal */
    if(sig_dis.set == 1 && sig_dis.act == 1)
    {
        sig = sig_dis.sig;
        /* This cannot continue */
        if(sig == SIGSEGV)
           return segv_handle(pid);
    }
    int status = ptrace(PTRACE_CONT, pid, NULL, sig);
    if(status == -1 && errno != 0)
    {
        fprintf(stderr, "continue failed : %s\n", strerror(errno));
    }

    /* we have sent the pending signal, remove them from queue */
    if(sig_dis.set == 1 && sig_dis.act == 1)
        rm_sig();
    return status;
}

/* This function gets user register data in regs for pid */
static int set_regs(struct user_regs_struct *regs, pid_t pid)
{

    int status = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if(status == -1 && errno != 0)
    {
        fprintf(stderr, "setreg failed : %s\n", strerror(errno));
    }
    return status;
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
    if(status == -1 && errno != 0)
    {
        fprintf(stderr, "getreg failed : %s %d\n", strerror(errno), pid);
    }
    return status;
}

/* Returns value of rbp */
static uintptr_t get_rbp(pid_t pid)
{
    struct user_regs_struct regs;
    if(get_regs(&regs, pid) == -1)
        return 0;
    return (uintptr_t)regs.rbp;
}

/* Returns value of rip */
static uintptr_t get_rip(pid_t pid)
{
    struct user_regs_struct regs;
    if(get_regs(&regs, pid) == -1)
        return 0;
    return (uintptr_t)regs.rip;
}
/* This function prints entire set of user registers one by one */
void print_all_regs(struct user_regs_struct *regs)
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
    errno = 0; /* clear errno before peeking */
    *word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr,
                         NULL);
    if(errno != 0)
    {
        fprintf(stderr, "peekdata failed : %s\n", strerror(errno));
        return -1;
    }

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
    if(addr == 0 || errno != 0)
        return -1;

    if(peek_long(addr, &word, pid) == -1)
        return -1;
    else
        printf("%lx\n", word);

    return 0;
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
        fprintf(stderr, "peekdata failed : %s\n", strerror(errno));
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

/* Function to remove breakpoint
bp: breakpoint data structure
Write the value at breakpoint addr back to
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

    bp->set = 1; /* this breakpoint is now set */

    return 0;
}

/* single step on each instruction */
static int step(pid_t pid)
{
    int sig = 0;
    /* check for pending signal */
    if(sig_dis.set == 1 && sig_dis.act == 1)
    {
        sig = sig_dis.sig;
        /* cannot continue after sigsegv */
        if(sig == SIGSEGV)
            return segv_handle(pid);
    }

    int status = ptrace(PTRACE_SINGLESTEP, pid, NULL, sig);
    if(status == -1 && errno != 0)
    {
        fprintf(stderr, "singlestep failed : %s\n", strerror(errno));
    }

    /* we have sent the pending signal, remove them from queue */
    if(sig_dis.set == 1 && sig_dis.act == 1)
        rm_sig();

    return status;
}

/* This function is called when breakpoint is hit
 * but we have reset register values and breakpoint address
 * to before we recieved SIGTAP. This will put breakpoint back before we can
 * either step or continue */
static int resume_bp(pid_t pid)
{
    if(bp.set == 2)
    {
        if(step(pid) == -1)
            return -1;
        pwait(pid, 0);
    }
}

/* Main stepping function checks for break points */
static int step_bp(pid_t pid)
{
    uintptr_t rip = get_rip(pid);

    /* check if there was a pending breakpoint */
    if(bp.set == 2)
    {
        bp.set = 1;
    }
    else if(bp.set == 1 && bp.addr == rip)
    {
            printf("Breakpoint hit at %lx\n", bp.addr);
            bp.set = 2;
            return 0;
    }

    if(step(pid) == -1)
        return -1;
    pwait(pid, 0);

    rip = get_rip(pid);
    if(bp.set == 1 && bp.addr == rip)
    {
        printf("Breakpoint hit at %lx\n", bp.addr);
        bp.set = 2;
    }
    else
    {
        printf("Stepped\n");
        regs_value(pid, "rip");
    }
    return 0;
}
/* This function resumes execution flow when debuggee is stopped because
 * 1.Signal was recieved by debuggee
 * 2. breakpoint was hit
 * 3. User sent "continue" command */
static int cont_bp(pid_t pid)
{
    int sig;

    /* check if there was a pending breakpoint */
    /*resuming from previous pending breakpoint, set it again */
    if(bp.set == 2)
    {
        if(resume_bp(pid) == -1)
            return -1;
        bp.set = 1;
    }
    if(bp.set == 1)
    {
        if(add_bp(&bp, pid) == -1)
           return -1;
    }

    /* call ptrace continue */
    if(cont(pid) == -1)
    {
        return -1;
    }
    sig = pwait(pid, 0);
    /* wait for either a signal or exit from debuggee*/
    if(sig == SIGTRAP && bp.set == 1)
    {
        printf("Breakpoint hit at %lx\n", bp.addr);
         /* we reset all values back to what they were before hitting breakpoint
         * so next time any command that runs should set the breakpoint back */
        if(unset_bp(&bp, pid) == -1)
        {
            printf("unset bp failed\n");
            return -1;
        }

        /* now we are in resume mode */
        /* there is a pending instruction which needs to be executed */
        bp.set = 2;
    }

    return 0;
}

/* This function is called when user sends delete command
 * It removes the break point or tells user if there is no
 * breakpoints currently active */
static int delete(pid_t pid)
{
    if(bp.set == 1)
    {
        bp.set = 0;
    }
    else if(bp.set == 2)
    {
        bp.set = 0;
    }
    else
    {
        printf("No breakpoint found\n");
        return 0;
    }
    bzero(&bp, sizeof(bp));
    printf("Breakpoint deleted\n");

    return 0;
}

/* Return address is stored just about rbp value pushed on stack
 * so to retrieve return address add WORD to rbp and
 * find value stored at that address */
static uintptr_t get_retaddr(uintptr_t rbp, pid_t pid)
{
    uintptr_t word;
    uintptr_t addr = rbp + WORD;
    if(peek_long(addr, &word, pid) == -1)
        return -1;

    return word;
}

/* get contents or rbp, check the return address
 * before rbp */
static int get_next_frame(uintptr_t *rbp, pid_t pid)
{
    uintptr_t word;
    /* what is at rbp */
    if(peek_long(*rbp, &word, pid) == -1)
        return -1;

    *rbp = word;
    word = get_retaddr(*rbp, pid);
    printf("%lx %lx \n", rbp, word);

    return 0;
}

/* get back trace */
/* let's do it for 5 levels */
static int bt(pid_t pid)
{
    /* start unwinding */
    uintptr_t rbp = get_rbp(pid);
    uintptr_t word = get_retaddr(rbp, pid);
    printf("%lx %lx \n", rbp, word);

    /* second */
    get_next_frame(&rbp, pid);
    /* third time */
    get_next_frame(&rbp, pid);

    return 0;
}

/* This function set the action for signals from debuggee
 */
static int p_sig(char *buf, pid_t pid)
{
    char *temp = strtok(NULL, "\n");
    if(temp == NULL)
    {
        printf("Current signal action: %s\n", sig_dis.act ? "pass" : "ignore");
        return 0;
    }
    if(strcmp(temp, "ignore" ) == 0)
    {
        unset_sig();
    }
    else if(strcmp(temp, "pass" ) == 0)
    {
        sig_dis.act = 1;
    }
    else
    {
        return -1;
    }

    return 0;
}

/* This function tells user if there are any breakpoints
 */
static void show()
{
    if(bp.set == 1 || bp.set == 2)
        printf("Breakpoint set at %lx\n", bp.addr);
    else
        printf("No breakpoint is set\n");
}

/* This function is called when user sends breakpoint command
 * It obtains addr for break point
 * Checks if breakpoint at this address is active
 * sets breakpoint on user provided address */
static int breakpoint(char *buf, pid_t pid)
{
    uintptr_t addr = 0;
    char *temp = strtok(NULL, " ");
    if(temp == NULL)
    {
        show();
        return 0;
    }

    addr = (uintptr_t)strtoul(temp, NULL, 16);
    if(addr == 0 || errno != 0)
        return -1;

    if(bp.set == 1 || bp.set == 2)
    {
        if(addr == bp.addr)
        {

            printf("Breakpoint already set on this address\n");
            return 0;
        }
        printf("No more breakpoints can be set\n");
        return 0;
    }

    bp.addr = addr;

    if(set_bp(&bp, pid) == -1)
        return -1;
    else
        printf("Breakpoint set at %lx\n", bp.addr);

    return 0;
}

/* prints help */
void help()
{
    char *help_str = "Commands supported\n"
        "help:      This command\n"
        "run:       run a (binary)\n"
        "attach:    Attach to (pid)\n"
        "detach:    Detach \n"
        "write:     Write (value) to (addr)\n"
        "read:      Read from (addr) \n"
        "regs:      Get register value(s). [reg name] optional \n"
        "step:      Go forward one instruction\n"
        "continue:  Continue \n"
        "break:     Set break point at (addr)\n"
        "break:      Show all breakpoints\n"
        "signal:    Set signal action to (pass) or (ignore)\n"
        "signal:    Show signal action \n"
        "backtrace: Show backtrace \n"
        "quit:      Exit from debugger\n" ;

    printf("%s", help_str);
}

/* detach the debuggee */
static int pdetach(pid_t pid)
{
    /* remove breakpoint data before detaching */
    if(bp.set == 1)
    {
        bp.set = 0;
    }
    else if(bp.set == 2)
    {
        if(resume_bp(pid) == -1)
            return -1;
        bp.set = 0;
    }

    if(detach(pid) == -1)
        return -1;

    clear_ds();
    tracee_pid = 0;
    printf("Process detached\n");
    return 0;
}

/* attach to the debuggee */
static int pattach(pid_t pid)
{
    int status = ptrace(PTRACE_ATTACH, pid, 0 ,0);
    if(status == -1 && errno != 0)
    {
        fprintf(stderr, "attach failed : %s\n", strerror(errno));
        return -1;
    }

    printf("Process attached\n");

    pwait(pid, 0);

    return 0;
}

/* Fork the binary, set PTRACEME and exec it*/
static int fork_exec(char *bin)
{
    errno = 0;
    pid_t pid = fork();
    if(pid == 0)
    {
        char *argv[] = {bin, NULL};
        int status;
        /* child */
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            return -1;

        errno = 0;
        status = execve(bin, argv, NULL);
        if(status == -1 || errno != 0)
        {
            fprintf(stderr, "execve error %s\n", strerror(errno));
            return -1;
        }
        /* good execve never returns */
    }
    else if (pid == -1)
    {
        fprintf(stderr, "fork error %s\n", strerror(errno));
        return -1;
    }
    else
    {
        /* parent */
        tracee_pid = pid;
        pwait(tracee_pid, 0);

    }
    return 0;
}

/* Run a given binary file name under ptrace */
static int run(char *buf)
{
    pid_t pid;
    char *bin = strtok(NULL, " \n");
    if(bin == NULL)
        return -1;
    errno = 0;
    int status = access(bin, R_OK | X_OK);
    if(status == -1 || errno != 0)
    {
        fprintf(stderr, "Access error %s\n", strerror(errno));
        return -1;
    }
    fork_exec(bin);

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

/* this is the main api which drives the debugger.
 * exit: 0 = quit, 1 = continue.
 * buf: commands and parameters in form of \n terminated line
 */
int dbg(int *exit, char *buf)
{
    int com = 0;
    char *token  = NULL;

    token = tokenise(buf);
    if(token == NULL)
        fprintf(stderr, "strtok failed : %s\n", strerror(errno));

    /* convert command into index */
    com = command_to_execute(token);
    switch(com)
    {
        case p_help:
            help();
            break;

        case p_run:
            if(run(buf) == -1)
                fprintf(stderr, "Cannot run this binary\n");
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
            if(step_bp(tracee_pid) == -1)
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

        case p_signal:
            if(p_sig(buf, tracee_pid) == -1)
                fprintf(stderr, "Cannot set signal action \n");
            break;

        case p_bt:
            if(bt(tracee_pid) == -1)
                fprintf(stderr, "Cannot get backtrace \n");
            break;

        case p_quit:
            /* exit clean by detaching before quiting */
            if(tracee_pid != 0)
                if(pdetach(tracee_pid) == -1)
                    fprintf(stderr ,"Coudn't detach before exit\n");
            *exit = 0;
            break;

        default:
            fprintf(stderr, "Unrecognised command."
                    "Type help to see supported commands\n");
            break;
    }

    return 0;
}

/* this function uses command line arguments to be fed to debugger
 * from argv[1] to argv[argc]
 * exit variable just keeps track of quit */
int tester_fn(int *exit, int argc, char **argv)
{
    int i = 0;
    for(i = 1; i < argc || exit == 0; i++)
        dbg(exit, argv[i]);

    return 0;
}

int main (int argc, char **argv)
{
    int exit = 1; /* The value is changed to zero when user calls quit command */
    char prompt[] = "(dbg):";
    char buf[buf_size];

    /* no debuggee at the beginning either */
    tracee_pid = 0;
    /* at the beginning no break point was set */
    bp.set = 0;

    /* this is to carry out testing */
    if(argc > 1)
        return tester_fn(&exit, argc, argv);

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
