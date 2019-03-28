/* This file contains helper function for debugger.
 * Some helper functions are for attach, detach, run, breakpoints etc.
 * Few function require basic parsing to get arguments.
 * */

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
#include <stddef.h>
#include <strings.h>
#include "dbg.h"
#include "commands.h"
#include "util/list.h"
#include "util/heap.h"

/* This is debuggee pid */
extern int tracee_pid;

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

/* breakpoint data structure list */
static struct list *bp_list = NULL;

/* Hardware Breakpoint data structure */
static struct hw_bp hw_bp;

/* Watchpoint data structure */
static struct wp wp;

/* last signal recieved and associated action */
struct sig_dis sig_dis;

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
    if (sig_dis.act == 1) {
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
    printf("siginfo = %d\n",siginfo.si_signo);
    if (siginfo.si_code == TRAP_BRKPT) {
    //    printf("Break point\n");
        return 0;
    }
    if (siginfo.si_code == TRAP_TRACE) {
      //  printf("Trace\n");
        return 0;
    }
    if (siginfo.si_code == SI_KERNEL) {
        //printf("Kernel\n");
        return 0;
    }
    if (siginfo.si_code == SI_USER) {
        //printf("User\n");
        return siginfo.si_signo;
    }
    return siginfo.si_signo;
}

/* This function takes an appropriate action based on
 * signal action settings */
static void set_sig(int sig)
{
    switch(sig) {
        case 0:
            break;
        case SIGTRAP:
            /* need a check if this is from debugger or debuggee */
            if (get_siginfo(tracee_pid))
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
    if (WIFEXITED(wstatus)) {
        printf("Debuggee exits with status %d\n", WEXITSTATUS(wstatus));
        /* debuggee has exited, reset tracee_pid */
        tracee_pid = 0;
    } else if (WIFSIGNALED(wstatus)) {
        sig = WTERMSIG(wstatus);
        printf("Debuggee killed by signal %d\n", sig);
        /* debuggee was killed, reset tracee_pid */
        tracee_pid = 0;
    } else if (WIFSTOPPED(wstatus)) {
        sig = WSTOPSIG(wstatus);
        set_sig(sig);
    } else if (WIFCONTINUED(wstatus)) {
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
    if (sig_dis.set == 1 && sig_dis.act == 1)
        sig = sig_dis.sig;

    int status = ptrace(PTRACE_DETACH, pid, 0 , sig);
    if (status == -1 && errno != 0) {
        fprintf(stderr, "detach failed : %s\n", strerror(errno));
        return -1;
    }

    /* we have sent the pending signal, remove them from queue */
    if (sig_dis.set == 1 && sig_dis.act == 1)
        rm_sig();

    return 0;
}

/* Free all breakpoint structures in the list */
static void rm_all_bp(void)
{
    if (bp_list) {
        struct list *temp = bp_list->head;
        while (temp) {
            struct list *next = temp->next;
            free(temp->element);
            temp->element = NULL;
            free(temp);
            temp = NULL;
            temp = next;
        }
    }
    bp_list = NULL;
}

/* reset all entries in signal and breakpoint data structure */
static void clear_ds()
{
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

/* This function read data from address
 * addr: address to which data should be read from
 * word: content at the address addr */
static int peek_long(uintptr_t addr, unsigned long *word, pid_t pid)
{
    errno = 0; /* clear errno before peeking */
    *word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr,
                         NULL);
    if (errno != 0) {
        fprintf(stderr, "peekdata failed : %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/* This function calls ptrace with PTRACE_CONT */
static int pcont(pid_t pid)
{
    int sig = 0;
    /* check for pending signal */
    if (sig_dis.set == 1 && sig_dis.act == 1) {
        sig = sig_dis.sig;
        /* This cannot continue */
        if (sig == SIGSEGV)
           return segv_handle(pid);
    }
    int status = ptrace(PTRACE_CONT, pid, NULL, sig);
    if (status == -1 && errno != 0) {
        fprintf(stderr, "continue failed : %s\n", strerror(errno));
    }

    /* we have sent the pending signal, remove them from queue */
    if (sig_dis.set == 1 && sig_dis.act == 1)
        rm_sig();
    return status;
}

/* This function read user data at offset
 * offset: offset to read  data  from
 * word: content at the address addr */
static int peek_user(uintptr_t offset, unsigned long *word, pid_t pid)
{
    errno = 0; /* clear errno before peeking */
    *word = ptrace(PTRACE_PEEKUSER, pid, offset,
                         NULL);
    if (errno != 0) {
        fprintf(stderr, "peekdata failed : %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/* Read value from debug register.
 * num: number of debug register 0 to 7
 * pid: pid of the debuggee */
static uintptr_t read_dr(int num, pid_t pid)
{
    unsigned long reg;
    uintptr_t offset = offsetof(struct user, u_debugreg[num]);
    peek_user(offset, &reg, pid);
    return reg;
}

static int cont_wp(pid_t pid)
{
    int sig;
    uintptr_t dr0, dr6, dr7;

    while (1)
    {
        if (pcont(pid) == -1) {
            return -1;
        }
        sig = pwait(pid, 0);
        /* wait for either a signal or exit from debuggee*/
        if (sig == SIGTRAP) {
            unsigned long word;
            if (wp.no_value) {
                printf("Watchpoint hit at %lx\n", wp.addr);
                break;
            }

            if (peek_long(wp.addr, &word, pid) == -1)
                return -1;
            if (wp.value == word) {
                printf("Watchpoint hit at %lx with value %lx\n", wp.addr, wp.value);
                break;
            } else
                continue;
        }
    }

    dr0 = (uintptr_t)read_dr(0, pid);
    printf("debug[0] = %lx\n", dr0);
    dr6 = (uintptr_t)read_dr(6, pid);
    printf("debug[6] = %lx\n", dr6);
    dr7 = (uintptr_t)read_dr(7, pid);
    printf("debug[7] = %lx\n", dr7);

    return 0;
}

/* Continue to handle hardware breakpoint.
 * We only arrive in this function when hardware breakpoint is set.
 * So there is no need to check if it was set or not.
 * */
static int cont_hw(pid_t pid)
{
    int sig;

    /* call ptrace continue */
    if (pcont(pid) == -1) {
        return -1;
    }
    sig = pwait(pid, 0);
    /* wait for either a signal or exit from debuggee*/
    if (sig == SIGTRAP) {
        uintptr_t dr0, dr6, dr7;
        printf("Breakpoint hit at %lx\n", hw_bp.addr);
        dr0 = (uintptr_t)read_dr(0, pid);
        printf("debug[0] = %lx\n", dr0);
        dr6 = (uintptr_t)read_dr(6, pid);
        printf("debug[6] = %lx\n", dr6);
        dr7 = (uintptr_t)read_dr(7, pid);
        printf("debug[7] = %lx\n", dr7);
    }

    return 0;
}

/* This function gets user register data in regs for pid */
static int set_regs(struct user_regs_struct *regs, pid_t pid)
{

    int status = ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if (status == -1 && errno != 0) {
        fprintf(stderr, "setreg failed : %s\n", strerror(errno));
    }
    return status;
}

/* This function will print contents of registers in regs data structure.
 * reg: Register for which value needs to be printed */
static void print_regs(struct user_regs_struct *regs, char *reg)
{
    if (strcmp(reg, "rax" ) == 0) {
        printf("rax 	0x%llx\n", regs->rax);
    } else if (strcmp(reg, "rbx" ) == 0) {
        printf("rbx 	0x%llx\n", regs->rbx);
    } else if (strcmp(reg, "rcx" ) == 0) {
        printf("rcx 	0x%llx\n", regs->rcx);
    } else if (strcmp(reg, "rdx" ) == 0) {
        printf("rdx 	0x%llx\n", regs->rdx);
    } else if (strcmp(reg, "rsi" ) == 0) {
        printf("rsi 	0x%llx\n", regs->rsi);
    } else if (strcmp(reg, "rdi" ) == 0) {
        printf("rdi 	0x%llx\n", regs->rdi);
    } else if (strcmp(reg, "rbp" ) == 0) {
        printf("rpb 	0x%llx\n", regs->rbp);
    } else if (strcmp(reg, "rsp" ) == 0) {
        printf("rsp 	0x%llx\n", regs->rsp);
    } else if (strcmp(reg, "r8" ) == 0) {
        printf("r8 	0x%llx\n", regs->r8);
    } else if (strcmp(reg, "r9" ) == 0) {
        printf("r9 	0x%llx\n", regs->r9);
    } else if (strcmp(reg, "r10" ) == 0) {
        printf("r10 	0x%llx\n", regs->r10);
    } else if (strcmp(reg, "r11" ) == 0) {
        printf("r11 	0x%llx\n", regs->r11);
    } else if (strcmp(reg, "r12" ) == 0) {
        printf("r12 	0x%llx\n", regs->r12);
    } else if (strcmp(reg, "r13" ) == 0) {
        printf("r13 	0x%llx\n", regs->r13);
    } else if (strcmp(reg, "r14" ) == 0) {
        printf("r14 	0x%llx\n", regs->r14);
    } else if (strcmp(reg, "r15" ) == 0) {
        printf("r15 	0x%llx\n", regs->r15);
    } else if (strcmp(reg, "rip" ) == 0) {
        printf("rip 	0x%llx\n", regs->rip);
    } else if (strcmp(reg, "eflags" ) == 0) {
        printf("eflags 	0x%llx\n", regs->eflags);
    } else if (strcmp(reg, "cs" ) == 0) {
        printf("cs 	0x%llx\n", regs->cs);
    } else if (strcmp(reg, "ss" ) == 0) {
        printf("ss 	0x%llx\n", regs->ss);
    } else if (strcmp(reg, "ds" ) == 0) {
        printf("ds 	0x%llx\n", regs->ds);
    } else if (strcmp(reg, "es" ) == 0) {
        printf("es 	0x%llx\n", regs->es);
    } else if (strcmp(reg, "fs" ) == 0) {
        printf("fs 	0x%llx\n", regs->fs);
    } else if (strcmp(reg, "gs" ) == 0) {
        printf("fs 	0x%llx\n", regs->fs);
    } else {
        printf("No such register %s\n", reg);
    }
}

/* This function gets value of user registers in regs data structure
 * for debuggee with process id pid */
static int get_regs(struct user_regs_struct *regs, pid_t pid)
{
    int status = ptrace(PTRACE_GETREGS, pid, NULL, regs);
    if (status == -1 && errno != 0) {
        fprintf(stderr, "getreg failed : %s %d\n", strerror(errno), pid);
    }
    return status;
}

/* Returns value of rbp */
static uintptr_t get_rbp(pid_t pid)
{
    struct user_regs_struct regs;
    if (get_regs(&regs, pid) == -1)
        return 0;
    return (uintptr_t)regs.rbp;
}

/* Returns value of rip */
static uintptr_t get_rip(pid_t pid)
{
    struct user_regs_struct regs;
    if (get_regs(&regs, pid) == -1)
        return 0;
    return (uintptr_t)regs.rip;
}

/* This function prints entire set of user registers one by one */
void print_all_regs(struct user_regs_struct *regs)
{
    int total_regs = sizeof(sregs)/sizeof(sregs[0]);
    int i = 0;

    for (i = 0; i < total_regs; i++)
        print_regs(regs, sregs[i]);
}

/* This function will obtain value for registers using get_regs() function
 * and print them.
 * regs: register whose value needs to obtained
 * if regs is NULL, value for all registers are printed */
static int regs_value(pid_t pid, char *reg)
{
    struct user_regs_struct regs;
    if (get_regs(&regs, pid) == -1)
        return -1;

    if (strcmp(reg, "all") == 0)
       print_all_regs(&regs);
    else
        print_regs(&regs, reg);

    return 0;
}

/* This function is called when user enters regs command.
 * It parses arguments for regs command to find which register's
 * value user want to see */
int regs(char *buf, pid_t pid)
{
    char *temp = strtok(NULL, "\n");

    if (temp == NULL)
        temp = "all";

    /* call regs_value to actually obtain regs data
     * and print register values */
    return regs_value(pid, temp);

}

/* Get breakpoint data structure from list at address addr.
 * if no matching breakpoint is found, return NULL.*/
static struct bp *get_bp_from_list(uintptr_t addr)
{
    struct bp *bp = NULL;
    if(!bp_list)
        return NULL;
    struct list *temp = bp_list->head;
    for (;temp; temp = temp->next) {
        bp = (struct bp*)temp->element;
        if(bp->addr == addr)
            return bp;
    }
    return NULL;
}

/* Get a breakpoint data structure.
 * If breakpoint exists at this address, return the associated ds.
 * If breakpoint doesn't exist, allocate a ds.
 * addr: address for breakpoint.
 * return: breakpoint data structure. */
static struct bp *get_bp_ds(uintptr_t addr)
{
    struct bp *bp = NULL;
    static unsigned int num_bp = 0;
    if (!bp_list) {
        /* at the beginning no break point was set */
        bp = (struct bp *)malloc(sizeof(*bp));
        bzero(bp, sizeof(*bp));
        num_bp++;
        bp->num = num_bp;
        bp_list = (struct list *)malloc(sizeof(*bp_list));
        list_init(bp_list, bp);
        return bp;
    } else {
        bp = get_bp_from_list(addr);
        if(bp)
            return bp;

        struct list *temp = (struct list *)malloc(sizeof(*bp_list));
        bp = (struct bp *)malloc(sizeof(*bp));
        bzero(bp, sizeof(*bp));
        num_bp++;
        bp->num = num_bp;
        list_add_next(&bp_list, bp, temp);
        assert(num_bp == get_num_members(bp_list));
        return bp;
    }
}

/* This function writes user data at offset
 * offset: offset to read  data  from
 * word: content at the address addr */
static int poke_user(uintptr_t offset, unsigned long word, pid_t pid)
{
    errno = 0; /* clear errno before peeking */
    int status  = ptrace(PTRACE_POKEUSER, pid, (void *)offset,
                         word);
    if (status == -1 && errno != 0) {
        fprintf(stderr, "peekdata failed : %s\n", strerror(errno));
    }
    return status;
}

/* Write a word to debug register.
 * word: Value to be written.
 * num: debug register number. */
static int write_dr(unsigned long word, int num, pid_t pid)
{
    uintptr_t offset = offsetof(struct user, u_debugreg[num]);
    if (poke_user(offset, word, pid) == -1)
        return -1;

    return 0;
}

/* write 0 to debug register.
 * num: debug register number. */
static int clear_dr(int num, pid_t pid)
{
    uintptr_t offset = offsetof(struct user, u_debugreg[num]);
    if (poke_user(offset, 0x0, pid) == -1)
        return -1;

    return 0;
}

/* This function is called when user enters read command.
 * It parses arguments for read command to find which address
 * value user want read */
int p_peek(char *buf, pid_t pid)
{
    uintptr_t addr = 0;
    unsigned long word = 0;

    char *temp = strtok(NULL, " \n");
    if (temp == NULL)
        return -1;


    addr = (uintptr_t)strtoul(temp, NULL, 16);
    if (addr == 0 || errno != 0)
        return -1;

    if (peek_long(addr, &word, pid) == -1)
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
    if (status == -1 && errno != 0) {
        fprintf(stderr, "peekdata failed : %s\n", strerror(errno));
    }
    return status;
}

/* This function is called when user enters write command.
 * It parses arguments for write command to find which address
 * value user want to write at and what content user want to write */
int p_poke(char *buf, pid_t pid)
{
    uintptr_t addr;
    unsigned long word;

    char *temp = strtok(NULL, " ");
    if (temp == NULL)
        return -1;

    addr  = (uintptr_t)strtoul(temp, NULL, 16);
    if (addr == 0 || errno != 0)
        return -1;

    temp = strtok(NULL, " \n");
    if (temp == NULL)
        return -1;

    word = strtoul(temp, NULL, 16);
    if (word == 0 || errno != 0)
        return -1;

    return poke_long(addr, word, pid);
}

/* Function to remove breakpoint
bp: breakpoint data structure
Write the value at breakpoint addr back to
 * what it was before breakpoint was set. */
static int rm_bp(struct bp *bp, pid_t pid)
{
    if (poke_long(bp->addr, bp->word, pid) == -1)
        return -1;
    //bp->set = 0;
}

 /*This function restores the value which was overwritten
  * at bp address. It also resets instruction pointer
  * back to bp address*/
static int unset_bp(struct bp *bp, pid_t pid)
{
    struct user_regs_struct regs;

    /* remove breakpoint */
    if (rm_bp(bp, pid) == -1)
        return -1;

    if (get_regs(&regs, pid) == -1)
        return -1;

    /* reset rip to previous value */
    regs.rip = bp->addr;

    return set_regs(&regs, pid);
}

/* This function overwrites value at breakpoint address with
 * trap instruction */
static int add_bp(struct bp *bp, pid_t pid)
{
    if (poke_long(bp->addr, bp->trap, pid) == -1)
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
    if (peek_long(bp->addr, &bp->word, pid) == -1)
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
    if (sig_dis.set == 1 && sig_dis.act == 1) {
        sig = sig_dis.sig;
        /* cannot continue after sigsegv */
        if (sig == SIGSEGV)
            return segv_handle(pid);
    }

    int status = ptrace(PTRACE_SINGLESTEP, pid, NULL, sig);
    if (status == -1 && errno != 0) {
        fprintf(stderr, "singlestep failed : %s\n", strerror(errno));
    }

    /* we have sent the pending signal, remove them from queue */
    if (sig_dis.set == 1 && sig_dis.act == 1)
        rm_sig();

    return status;
}

/* This function is called when breakpoint is hit
 * but we have reset register values and breakpoint address
 * to before we recieved SIGTAP. This will put breakpoint back before we can
 * either step or continue */
static int resume_bp(struct bp *bp, pid_t pid)
{
    /* we already know breakpoint was in resume mode before we come here */
    if (bp->set == 2) {
        if (step(pid) == -1)
            return -1;
        pwait(pid, 0);
    }
}

/* Main stepping function checks for break points */
int step_bp(pid_t pid)
{
    struct bp *bp = NULL;
    uintptr_t rip = get_rip(pid);

    bp = get_bp_from_list(rip);
    if (bp) {
        /* check if there was a pending breakpoint */
        if (bp->set == 2) {
            bp->set = 1;
        } else if (bp->set == 1 && bp->addr == rip) {
            printf("Breakpoint hit at %lx\n", bp->addr);
            bp->set = 2;
            return 0;
        }
    }

    if (step(pid) == -1)
        return -1;
    pwait(pid, 0);

    rip = get_rip(pid);
    bp = get_bp_from_list(rip);
    if (bp && bp->set == 1 && bp->addr == rip) {
        printf("Breakpoint hit at %lx\n", bp->addr);
        bp->set = 2;
    } else {
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
    struct list *temp = NULL;
    struct bp *bp = NULL;
    if(bp_list)
        temp = bp_list->head;
    /* check if there was a pending breakpoint */
    /*resuming from previous pending breakpoint, set it again */
    for (; temp; temp = temp->next)
    {
        bp = (struct bp *)temp->element;

        if (bp->set == 2) {
            if (resume_bp(bp, pid) == -1)
                return -1;
            bp->set = 1;
        }
        if (bp->set == 1) {
            if (add_bp(bp, pid) == -1)
                return -1;
        }
    }
    /* call ptrace continue */
    if (pcont(pid) == -1) {
        return -1;
    }
    sig = pwait(pid, 0);
    /* wait for either a signal or exit from debuggee*/
    if (sig == SIGTRAP) {
        uintptr_t rip = get_rip(pid);
        bp = NULL;
        rip = rip - 1;
        bp = get_bp_from_list(rip);
        if (bp != NULL && bp->set == 1) {
            printf("Breakpoint hit at %lx\n", bp->addr);
            /* we reset all values back to what they were before hitting breakpoint
             * so next time any command that runs should set the breakpoint back */
            if (unset_bp(bp, pid) == -1) {
                printf("unset bp failed\n");
                return -1;
            }
            /* now we are in resume mode */
            /* there is a pending instruction which needs to be executed */
            bp->set = 2;
        }
    }

    /* we are reusing the list variable */
    temp = NULL;
    if(bp_list)
        temp = bp_list->head;
    /* stupid overhead to make sure every set breakpoint is removed */
    for (; temp; temp = temp->next) {
        bp = (struct bp *)temp->element;
        if (bp->set == 1) {
            /* remove breakpoint */
            if (rm_bp(bp, pid) == -1)
                return -1;
        }
    }

    return 0;
}

/* This is main continue function.
 * pid process id for debuggee
 * Do we allow both software and hardware breakpoint at the same time?
 * Let's assume here that only one type of breakpoint is set:
 * Each of them have their own function.
 */
int cont(pid_t pid)
{
    if (hw_bp.set == 1)
        return cont_hw(pid);
    else if (wp.set == 1)
        return cont_wp(pid);
    else
       return cont_bp(pid);
}

/* This function is called when user sends delete command
 * It removes the break point or tells user if there is no
 * breakpoints currently active */
int delete(char *buf, pid_t pid)
{
    uintptr_t addr = 0;
    struct bp *bp = NULL;
    char *temp = strtok(NULL, " ");
    if (temp == NULL) {
        rm_all_bp();
        printf("All breakpoints removed\n");
        return 0;
    }

    addr = (uintptr_t)strtoul(temp, NULL, 16);
    if (addr == 0 || errno != 0)
        return -1;

    bp = get_bp_from_list(addr);
    if (!bp) {
        printf("No breakpoint found\n");
        return 0;
    }

    if (bp->set == 1) {
        bp->set = 0;
    } else if (bp->set == 2) {
        bp->set = 0;
    } else {
        printf("No breakpoint found\n");
        return 0;
    }
    bzero(bp, sizeof(*bp));
    printf("Breakpoint deleted\n");

    return 0;
}

/* callq's opcode is E8 for near calls
 * We find where in last 8 bytes is e*8
 */
static int whereis_e8(uintptr_t word)
{
    uintptr_t e8 = 0xe8;
    int pos = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (word & e8) {
            pos = i;
            break;
        }
        e8 <<= 8;
    }

    return pos;
}

/* How much offset from current point into
 * the function call */
static long long find_offset(int shift, uintptr_t word)
{
    uintptr_t mask = 0xffffffffffffffff;
    long long offset;
    mask <<= (shift + 1) * 8;
    offset = word & mask;
    offset =  offset >> (sizeof(int) * 8);
   // printf("offset = %ld %lx %d\n", offset, mask, shift);

    return offset;
}

/* Find the address address of function which was called.
 */
static int get_fnaddr(uintptr_t ret, pid_t pid)
{

    uintptr_t word;
    uintptr_t addr = ret - WORD;
    long long offset;
    int shift;

    /* so we will peak 8 bytes before the return address */
    if (peek_long(addr, &word, pid) == -1)
        return -1;
    //printf("fn here = %lx \n", word);

    /* locate where is callq instruction */
    shift = whereis_e8(word);
    offset = find_offset(shift, word);
    //printf("call point = %lx\n",addr + shift);
    printf("%lx\n", (uintptr_t)((long long)ret + offset));

    return 0;
}

/* Return address is stored just about rbp value pushed on stack
 * so to retrieve return address add WORD to rbp and
 * find value stored at that address */
static int get_retaddr(uintptr_t rbp, pid_t pid, uintptr_t *ret)
{
    uintptr_t addr = rbp + WORD;
    if (peek_long(addr, ret, pid) == -1)
        return -1;

    return 0;
}

/* get contents or rbp, check the return address
 * before rbp */
static int get_next_frame(uintptr_t *rbp, pid_t pid)
{
    uintptr_t word;
    /* what is at rbp */
    if (peek_long(*rbp, &word, pid) == -1)
        return -1;

    *rbp = word;

    if (get_retaddr(*rbp, pid, &word) == -1)
        return -1;

    //printf("%lx %lx \n", rbp, word);
    return get_fnaddr(word, pid);

}

/* get back trace
 * let's do it for 5 levels */
int bt(pid_t pid)
{
    uintptr_t word;

    /* start unwinding */
    uintptr_t rbp = get_rbp(pid);

    /* getting rbp failed for some reason */
    if (rbp == 0)
        return -1;

    if (get_retaddr(rbp, pid, &word) == -1)
        return -1;

    //printf("%lx %lx \n", rbp, word);
    if (get_fnaddr(word, pid) == -1)
        return -1;

    /* we would want another condition besides i <2 ? */
    for (int i = 0; i < 2; i++) {
        if ( get_next_frame(&rbp, pid) == -1)
            return -1;
    }

    return 0;
}

/* This function set the action for signals from debuggee
 */
int p_sig(char *buf, pid_t pid)
{
    char *temp = strtok(NULL, "\n");
    if (temp == NULL) {
        printf("Current signal action: %s\n", sig_dis.act ? "pass" : "ignore");
        return 0;
    }
    if (strcmp(temp, "ignore" ) == 0) {
        unset_sig();
    } else if (strcmp(temp, "pass" ) == 0) {
        sig_dis.act = 1;
    } else {
        return -1;
    }

    return 0;
}

/*  show watchpoint */
static void show_wp()
{
    if (wp.set == 1) {
            printf("Watchpoint set at %lx\n", wp.addr);
            return;
    }
    printf("No watchpoint is set\n");
}

/* show hardware breakpoints*/
static void show_hw()
{
    if (hw_bp.set == 1) {
            printf("Hardware breakpoint set at %lx\n", hw_bp.addr);
            return;
    }
    printf("No breakpoint is set\n");
}

/* This function tells user if there are any breakpoints
 */
static void show_bp()
{
    struct bp *bp = NULL;

    if (!bp_list) {
        printf("No breakpoint is set\n");
        return;
    }
    struct list *temp = bp_list->head;
    for (; temp; temp = temp->next) {
        struct bp *bp = (struct bp *)temp->element;
        if (bp->set == 1 || bp->set == 2)
            printf("Breakpoint %d set at %lx\n",bp->num, bp->addr);
    }
}

/* remove hardware breakpoint */
static int rm_hw_bp(pid_t pid, int num)
{
    /* set all debug registers to zero */
    if (write_dr(0, num, pid) == -1)
        return -1;
    if (write_dr(0, 6, pid) == -1)
        return -1;
    if (write_dr(0, 7, pid) == -1)
        return -1;

    hw_bp.set = 0;
}

/* This function is called when user sends delete command
 * It removes the break point or tells user if there is no
 * breakpoints currently active */
int remove_hw(pid_t pid)
{
    if (hw_bp.set == 1) {
        rm_hw_bp(pid, 0);
    } else {
        printf("No harware breakpoint found\n");
        return 0;
    }
    bzero(&hw_bp, sizeof(hw_bp));
    printf("Hardware Breakpoint deleted\n");

    return 0;
}

/*set hardware break point */
static int set_hw_bp(uintptr_t addr, int num, pid_t pid)
{
    uintptr_t dr7; /* Actual setting for breakpoints */

    /* for first break point bits to be set.
     * 1:   L0
     * 8:   LE
     * 9:   GE
     * 10:  reserved
     * 11100000001*/
    dr7 = 0x701;

    hw_bp.addr = addr;
    if (write_dr(dr7, 7, pid) == -1)
        return -1;
    if (write_dr(hw_bp.addr, 0, pid) == -1)
        return -1;

    /* writing dr is successful, let's update global hw bp variable. */
    hw_bp.set = 1;

    printf("Hardware breakpoint set at %lx\n", addr);
    return 0;
}

/* This function is called when user sends hardware command
 * It obtains addr for break point
 * Checks if breakpoint at this address is active
 * sets breakpoint on user provided address */
int hw(char *buf, pid_t pid)
{
    uintptr_t addr = 0;
    if (bp_list) {
        printf("Software breakpoints are in use\n");
        return 0;
    }

    if (wp.set == 1) {
        printf("Watchpoints are in use\n");
        return 0;
    }

    char *temp = strtok(NULL, " ");
    if (temp == NULL) {
        show_hw();
        return 0;
    }
    addr = (uintptr_t)strtoul(temp, NULL, 16);
    if (addr == 0 || errno != 0)
        return -1;

    if (set_hw_bp(addr, 0, pid) == -1)
        return -1;
    return 0;
}

/* so the actual work happens here */
static int set_wp(uintptr_t addr, long value, int no_value, pid_t pid)
{
    uintptr_t dr7; /* Actual setting for watchpoint */

    /* for first watchpoint bits to be set.
     * 1:       L0
     * 9:       LE
     * 10:      GE
     * 11:      reserved
     * 17-18:   RW0
     * 19-20:   LEN0
     * 11010000011100000001*/
    dr7 = 0xD0701;

    if (write_dr(dr7, 7, pid) == -1)
        return -1;
    if (write_dr(addr, 0, pid) == -1)
        return -1;

    wp.set = 1;
    wp.no_value = no_value;
    wp.addr = addr;
    wp.value = value;
    wp.num = 1;

    printf("Watchpoint set at %lx\n", addr);

    /* so we need to add write monitor and read 4 bytes */
    return 0;
}

/* This function is called when user calls watch command.
 * It parses arguments for watch command to find which address
 * value user want to watch at and what value user want at this address. */
int watch(char *buf, pid_t pid)
{
    uintptr_t addr;
    long word; /* so the value could be signed or unsigned. */
    int no_value = 0;

    if (bp_list) {
        printf("Software breakpoints are in use\n");
        return 0;
    }

    if (hw_bp.set == 1) {
        printf("Hardware breakpoints are in use\n");
        return 0;
    }

    char *temp = strtok(NULL, " ");
    if (temp == NULL) {
        show_wp();
        return 0;
    }

    addr  = (uintptr_t)strtoul(temp, NULL, 16);
    if (addr == 0 || errno != 0)
        return -1;

    temp = strtok(NULL, " \n");
    if (temp == NULL) {
        /* so we just watch on address */
        no_value = 1;
    } else {
        errno = 0;
        word = strtol(temp, NULL, 10);
        if (errno != 0)
            return -1;
    }

    return set_wp(addr, word, no_value, pid);
}

/* This function is called when user sends breakpoint command
 * It obtains addr for break point
 * Checks if breakpoint at this address is active
 * sets breakpoint on user provided address */
int breakpoint(char *buf, pid_t pid)
{
    uintptr_t addr = 0;
    if (hw_bp.set == 1) {
        printf("Hardware breakpoints are in use\n");
        return 0;
    }

    if (wp.set == 1) {
        printf("watchpoints are in use\n");
        return 0;
    }

    char *temp = strtok(NULL, " ");
    struct bp *bp = NULL;
    if (temp == NULL) {
        show_bp();
        return 0;
    }

    addr = (uintptr_t)strtoul(temp, NULL, 16);
    if (addr == 0 || errno != 0)
        return -1;

    bp = get_bp_ds(addr);
    if (bp->set == 1 || bp->set == 2) {
        if (addr == bp->addr) {

            printf("Breakpoint already set on this address\n");
            return 0;
        }
        printf("No more breakpoints can be set\n");
        return 0;
    }

    bp->addr = addr;

    if (set_bp(bp, pid) == -1)
        return -1;
    else
        printf("Breakpoint %d set at %lx\n",bp->num, bp->addr);

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
        "break:     Show all breakpoints\n"
        "delete:    Delete breakpoint at (addr)\n"
        "signal:    Set signal action to (pass) or (ignore)\n"
        "signal:    Show signal action \n"
        "backtrace: Show backtrace \n"
        "hardware:  Set Hardware breakpoint at (address)\n"
        "remove:    Delete Hardware breakpoint.\n"
        "watch:     Set watchpoint at (addr) for (value).\n"
        "quit:      Exit from debugger\n" ;

    printf("%s", help_str);
}

void exit_dbg(void)
{
    rm_all_bp();
    clear_ds();
    tracee_pid = 0;
}

/* detach the debuggee */
int pdetach(pid_t pid)
{
    struct list *temp = NULL;
    if (bp_list)
        temp = bp_list->head;
    for (; temp; temp = temp->next) {
        /* remove breakpoint data before detaching */
        struct bp *bp = (struct bp *)temp->element;
        if (bp->set == 1) {
            bp->set = 0;
        } else if (bp->set == 2) {
            if (resume_bp(bp, pid) == -1)
                return -1;
            bp->set = 0;
        }
    }
    /* remove any hardware breakpoints before leaving */
    if (hw_bp.set == 1)
        rm_hw_bp(pid, 0);

    if (detach(pid) == -1)
        return -1;

    exit_dbg();
    printf("Process detached\n");
    return 0;
}

/* attach to the debuggee */
int pattach(pid_t pid)
{
    int status = ptrace(PTRACE_ATTACH, pid, 0 ,0);
    if (status == -1 && errno != 0) {
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
    if (pid == 0) {
        char *argv[] = {bin, NULL};
        int status;
        /* child */
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            return -1;

        errno = 0;
        status = execve(bin, argv, NULL);
        if (status == -1 || errno != 0) {
            fprintf(stderr, "execve error %s\n", strerror(errno));
            return -1;
        }
        /* good execve never returns */
    } else if (pid == -1) {
        fprintf(stderr, "fork error %s\n", strerror(errno));
        return -1;
    } else {
        /* parent */
        tracee_pid = pid;
        pwait(tracee_pid, 0);

    }
    return 0;
}

/* Run a given binary file name under ptrace */
int run(char *buf)
{
    pid_t pid;
    char *bin = strtok(NULL, " \n");
    if (bin == NULL)
        return -1;
    errno = 0;
    int status = access(bin, R_OK | X_OK);
    if (status == -1 || errno != 0) {
        fprintf(stderr, "Access error %s\n", strerror(errno));
        return -1;
    }
    fork_exec(bin);

    return 0;
}

static void
int_handler(int sig, siginfo_t *siginfo, void *ucontext)
{
    if (sig == SIGINT)
        printf("Debugger interrupted\n");
    else
        fprintf(stderr, "This shouldn't be happening\n");
}

/* let's register signal handler for debugger
 * especially SIGINT */
static void reg_signals()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    const struct sigaction act = {
        .sa_sigaction = int_handler,
        .sa_mask = mask,
        .sa_flags = 0,
    };
    sigaction(SIGINT, &act, 0);
}

void init_dbg()
{
    reg_signals();
    /* no debuggee at the beginning either */
    tracee_pid = 0;
    /* at the beginning no hardware break point was set */
    hw_bp.set = 0;
}
