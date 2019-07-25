/* This file contains functions for debugger, which provide functionality
 * for commands corresponding to debugger.
 * Also contains Auxillary functions for maintainibility reasons.
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

/* string for integer register names */
char sregs[][WORD]  = {
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
/* NOTE: Supports one hardware breakpoint. */
static struct hw_bp hw_bp;

/* Watchpoint data structure */
/* NOTE: Supports one watchpoint. */
static struct wp wp;

/* last signal recieved and associated action. */
struct sig_dis sig_dis;

/* Remove signal from sig_dis data structure. */
static void rm_sig()
{
        sig_dis.sig = 0;
        sig_dis.set = 0;
}

/* Reset sig_dis data structure to ignore signals. */
static void unset_sig()
{
        sig_dis.act = 0;
        rm_sig();
}

/* Add signal to the sig_dis */
static void add_sig(int sig)
{
        /* If signal action is pass, we add signal to data sig_dis structure. */
        if (sig_dis.act == 1) {
                sig_dis.sig = sig;
                sig_dis.set = 1;
        }
}

/* Get more information about SIGTRAP.
 * NOTE: This function could still be used to get
 * more information about other functions, but we are not
 * using that functionality.
 */
static int get_siginfo(pid_t pid)
{
        siginfo_t siginfo;
        ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);
        printf("siginfo = %d\n",siginfo.si_signo);

        /* If this is TRAP_TRACE and TRAP_BRKPT
         * it is from debugee, else it is from user */

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

/* Take an appropriate action based on
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

/* Use waitpid() on pid to check status of debuggee process,
 * when it exits or recieves a signal.
 * options: Waitpid options. Currently not really used.
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
                /* we have recieved a signal, take a note of this signal. */
                set_sig(sig);
        } else if (WIFCONTINUED(wstatus)) {
                printf("Debuggee continues\n");
        }

        return sig;
}

/*  Provide ptrace_detach functionality and signals housekeeping after detach. */
static int detach(pid_t pid)
{
        int sig = 0;
        int status;

        /* are there any pending signal */
        if (sig_dis.set == 1 && sig_dis.act == 1)
                sig = sig_dis.sig;

        errno = 0;
        status = ptrace(PTRACE_DETACH, pid, 0 , sig);
        if (status == -1 && errno != 0) {
                fprintf(stderr, "detach failed : %s\n", strerror(errno));
                return -1;
        }

        /* we have sent the pending signal, remove them from queue */
        if (sig_dis.set == 1 && sig_dis.act == 1)
                rm_sig();

        return 0;
}

/* Free all breakpoint structures in the list.
 * NOTE: Any function calling this routing should check if
 * bp_list is NULL. */

static void rm_all_bp(void)
{
        /* This might need resturcturing */
        /* for now we are embedding structures in list,
         * a better implmentation is other way round */
        struct list *temp = bp_list->head;
        while (temp) {
                struct list *next = temp->next;
                free(temp->element);
                temp->element = NULL;
                free(temp);
                temp = NULL;
                temp = next;
        }
        bp_list = NULL;
}

/* reset all entries in signal structure. */
static void clear_ds()
{
        rm_sig();
}

/* Handler for pending SIGSEGV. */
static int segv_handle(pid_t pid)
{
        /* we want to send the signal by detach command */
        detach(pid);
        /* remove any pending signals */
        clear_ds();
        tracee_pid = 0;
        return 0;
}

/* Read word size data from address using PEEKDATA.
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

/* Call ptrace with PTRACE_CONT.
 * Also check for delivery of any pending singals. */
static int pcont(pid_t pid)
{
        int sig = 0;
        int status;
        /* check for pending signal */
        if (sig_dis.set == 1 && sig_dis.act == 1) {
                sig = sig_dis.sig;
                /* This cannot continue */
                if (sig == SIGSEGV)
                        return segv_handle(pid);
        }
        errno = 0;
        status = ptrace(PTRACE_CONT, pid, NULL, sig);
        if (status == -1 && errno != 0) {
                fprintf(stderr, "continue failed : %s\n", strerror(errno));
        }

        /* we have sent the pending signal, remove them from queue */
        if (sig_dis.set == 1 && sig_dis.act == 1)
                rm_sig();
        return status;
}

/* Read word size user data at given offset.
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
        if(peek_user(offset, &reg, pid) == -1)
                return -1;
        return reg;
}

/* Continue if watchpoint is set */
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
                        /* When watchpoint is set on an address, however
                         * no value for watchpoint data is provided */
                        if (wp.no_value) {
                                printf("Watchpoint hit at %lx\n", wp.addr);
                                break;
                        }

                        /* current value at watchpoint address */
                        if (peek_long(wp.addr, &word, pid) == -1)
                                return -1;

                        /* BUG: so when user provides a value and we past that value ? */
                        if (wp.value == word) {
                                printf("Watchpoint hit at %lx with value %lx\n",
                                       wp.addr, wp.value);
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
 * NOTE: We only arrive in this function when hardware breakpoint is set.
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
        /* BUG: We might want to add more checks here, so we know it is not user
         * SIGTRAP. */
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

/* Print contents of registers in regs data structure.
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

/* Get value of user registers.
 * regs: register data structure to get register values. */
static int get_regs(struct user_regs_struct *regs, pid_t pid)
{
        int status;
        errno = 0;
        status = ptrace(PTRACE_GETREGS, pid, NULL, regs);
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

/* Print entire set of user registers one by one. */
void print_all_regs(struct user_regs_struct *regs)
{
        int total_regs = sizeof(sregs)/sizeof(sregs[0]);
        int i = 0;

        for (i = 0; i < total_regs; i++)
                print_regs(regs, sregs[i]);
}

/* Obtain value for registers using get_regs() function
 * and print them.
 * NOTE: if regs is NULL, value for all registers are printed.
 * regs: register whose value needs to obtained. */
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

int regs(char *buf, pid_t pid)
{
        char *temp = strtok(NULL, "\n");

        if (temp == NULL)
                temp = "all";

        /* call regs_value to actually obtain regs data
         * and print register values */
        return regs_value(pid, temp);
}

/* Get breakpoint data structure from breakpoint list.
 * addr: Address to match.
 * return: NULL, if address doesn't match. */
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
 * addr: address for breakpoint.
 * return: breakpoint data structure. */
static struct bp *get_bp_ds(uintptr_t addr)
{
        struct bp *bp = NULL;
        static unsigned int num_bp = 0;
        /* If breakpoint doesn't exist, allocate a ds. */
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
                /* If breakpoint exists at addr, return the associated ds. */
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

/* Write user data at offset.
 * offset: offset to read  data  from
 * word: content at the address addr */
static int poke_user(uintptr_t offset, unsigned long word, pid_t pid)
{
        int status;
        errno = 0; /* clear errno before peeking */
        status  = ptrace(PTRACE_POKEUSER, pid, (void *)offset,
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

/* Writes data to an address.
 * addr: address to which data should be written
 * word: content to be written to address addr */
static int poke_long(uintptr_t addr, unsigned long word, pid_t pid)
{
        int status;
        errno = 0;
        status  = ptrace(PTRACE_POKEDATA, pid, (void *)addr,
                         word);
        if (status == -1 && errno != 0) {
                fprintf(stderr, "peekdata failed : %s\n", strerror(errno));
        }
        return status;
}

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

/* remove hardware breakpoint.
 * num: the number of debug register.
 * */
static int clear_drs(pid_t pid, int num)
{
        /* set all debug registers to zero */
        if (write_dr(0, num, pid) == -1)
                return -1;
        if (write_dr(0, 6, pid) == -1)
                return -1;
        if (write_dr(0, 7, pid) == -1)
                return -1;

        return 0;
}

/* delete watchpoint */
static int remove_wp(uintptr_t addr, pid_t pid)
{
        /* clear all debug registers. */
        if (clear_drs(pid, 0) == -1)
                return -1;
        /* clear watchpoint data structure */
        bzero(&wp, sizeof(wp));
        printf("Watchpoint deleted\n");

        return 0;
}

/* Delete hardware breakpoint */
static int remove_hw(uintptr_t addr, pid_t pid)
{
        /* clear all debug registers */
        clear_drs(pid, 0);
        /* clear hardware breakpoint data structure */
        bzero(&hw_bp, sizeof(hw_bp));
        printf("Hardware Breakpoint deleted\n");

        return 0;
}

/* Restore original value stored at breakpoint address.
 * bp: breakpoint data structure
 */
static int rm_bp(struct bp *bp, pid_t pid)
{
        return poke_long(bp->addr, bp->word, pid);
}

/* Revert value at breakpoint address from trap instruction
 * to its orginal value. Resets instruction pointer
 * back to bp address. */
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

/* Overwrite value at breakpoint address with
 * trap instruction. */
static int add_bp(struct bp *bp, pid_t pid)
{
        if (poke_long(bp->addr, bp->trap, pid) == -1)
                return -1;

        bp->set = 1; /* this breakpoint is now set */
        return 0;
}

/* Save value at breakpoint address and create
 * a suitable value for trap instruction to
 * set breakpoint */
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

/* Single step on each instruction. */
static int step(pid_t pid)
{
        int sig = 0;
        int status;
        /* check for pending signal */
        if (sig_dis.set == 1 && sig_dis.act == 1) {
                sig = sig_dis.sig;
                /* cannot continue after sigsegv */
                if (sig == SIGSEGV)
                        return segv_handle(pid);
        }

        errno = 0;
        status = ptrace(PTRACE_SINGLESTEP, pid, NULL, sig);
        if (status == -1 && errno != 0) {
                fprintf(stderr, "singlestep failed : %s\n", strerror(errno));
        }

        /* we have sent the pending signal, remove them from queue */
        if (sig_dis.set == 1 && sig_dis.act == 1)
                rm_sig();

        return status;
}

/* Resume execution after breakpoint was hit.
 * When breakpoint is hit we have reset RIP back by one byte
 * So when we resume exection after breakpoint is hit, we don't want
 * to execute same instruction again with breakpoint set, so we step once.*/
static int resume_bp(struct bp *bp, pid_t pid)
{
        /* we already know breakpoint was in resume mode before we come here */
        if (bp->set == 2) {
                if (step(pid) == -1)
                        return -1;
                pwait(pid, 0);
        }
        return 0;
}

int step_bp(pid_t pid)
{
        struct bp *bp = NULL;
        uintptr_t rip = get_rip(pid);

        /* check for stepping in and out from a software breakpoint. */
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

/* This function resumes execution flow when debuggee is stopped.
 * Source of execution halt can be:
 * 1. Signal was recieved by debuggee
 * 2. breakpoint was hit
 * 3. Debuggee finished execution or was killed. */
static int cont_bp(pid_t pid)
{
        int sig;
        struct list *temp = NULL;
        struct bp *bp = NULL;
        if(bp_list)
                temp = bp_list->head;
        for (; temp; temp = temp->next)
        {
                bp = (struct bp *)temp->element;

                /* check if there was a pending breakpoint */
                /*resuming from previous pending breakpoint, set it again */
                if (bp->set == 2) {
                        if (resume_bp(bp, pid) == -1)
                                return -1;
                        bp->set = 1;
                }
                /* add TRAP instuction at the address */
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

int cont(pid_t pid)
{
        /* at any given time only one of the following is active
         * 1. Hardware breakpoint */
        if (hw_bp.set == 1)
                return cont_hw(pid);
        /* 2. Watchpoint */
        else if (wp.set == 1)
                return cont_wp(pid);
        /* 3. Software breakpoint and general continuation */
        else
                return cont_bp(pid);
}

/* Remove software breakpoint from breakpoint list.
 * addr: address for breakpoint to be removed*/
static int remove_bp(uintptr_t addr)
{
        struct bp *bp = NULL;

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

int delete(char *buf, pid_t pid)
{
        uintptr_t addr = 0;
        char *temp = strtok(NULL, " ");
        if (temp == NULL) {
                /* if no argument is provided remove all breakpoints */
                if (bp_list) {
                        rm_all_bp();
                        printf("All breakpoints removed\n");
                        return 0;
                }
                /* TODO: Add removal of any watch or hw breakpoints */
        } else {
                errno = 0;
                addr = (uintptr_t)strtoul(temp, NULL, 16);
                if (addr == 0 || errno != 0)
                        return -1;
        }

        /* Remove either hw or sw bp or wp */
        if (hw_bp.set == 1) {
                return remove_hw(addr, pid);
        }

        if (wp.set == 1) {
                return remove_wp(addr, pid);
        }

        if(bp_list)
                remove_bp(addr);

        return 0;
}

/* Find the byte which contains e8 value.
 * opcode for callq is E8 for near calls. */
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

/* Find offset from current point into
 * the function call. */
static long long find_offset(int shift, uintptr_t word)
{
        uintptr_t mask = 0xffffffffffffffff;
        long long offset;
        /* unset every bit until the shift bit. */
        mask <<= (shift + 1) * 8;
        /* we have removed all lower bits. */
        offset = word & mask;
        /* move higher bits towards lower bits */
        /* why the fuck did  I used sizeof(int) though? */
        offset =  offset >> (sizeof(int) * 8);
        // printf("offset = %ld %lx %d\n", offset, mask, shift);

        return offset;
}

/* Find the return address of function which was called.
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
        /* so we are printing the address before return by offset bytes */
        printf("%lx\n", (uintptr_t)((long long)ret + offset));

        return 0;
}

/* Obtain Return address of funtion by looking into stack.
 * Return address is stored just about rbp value pushed on stack
 * so to retrieve return address add WORD to rbp and
 * find value stored at that address */
static int get_retaddr(uintptr_t rbp, pid_t pid, uintptr_t *ret)
{
        uintptr_t addr = rbp + WORD;
        if (peek_long(addr, ret, pid) == -1)
                return -1;

        return 0;
}

/* Get frame content for next frame.
 * get contents of rbp, check the return address
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

int bt(pid_t pid)
{
        uintptr_t word;

        /* start unwinding */
        uintptr_t rbp = get_rbp(pid);

        /* getting rbp failed for some reason */
        if (rbp == 0)
                return -1;

        /* obtain return address for the function stored in rbp */
        if (get_retaddr(rbp, pid, &word) == -1)
                return -1;

        //printf("%lx %lx \n", rbp, word);
        /* Obtain function address by finding argument to callq */
        if (get_fnaddr(word, pid) == -1)
                return -1;

        /* TODO: we would want another condition besides i <2 ? */
        /* Keep obtaining next from stack until a given condition is
         * satisfied. */
        for (int i = 0; i < 2; i++) {
                if ( get_next_frame(&rbp, pid) == -1)
                        return -1;
        }

        return 0;
}

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

/* Show address for software breakpoints. */
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

/*set hardware break point.
 * addr: address for breakpoint.
 * num: 1 of 4 breakpoints. */
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
        /* write above value for setting the breakpoint */
        if (write_dr(dr7, 7, pid) == -1)
                return -1;
        /* write address on which breakpoint should be activated. */
        if (write_dr(hw_bp.addr, num, pid) == -1)
                return -1;

        /* writing dr is successful, let's update global hw bp variable. */
        hw_bp.set = 1;

        printf("Hardware breakpoint set at %lx\n", addr);
        return 0;
}

int hw(char *buf, pid_t pid)
{
        uintptr_t addr = 0;

        /* check if any other kinds of tracepoints are active */
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
                /* if no argument is provided show all set hw breakpoints */
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

/* Set watchpoints.
 * addr:    address to be watched.
 * value:   Value to lookout for.
 * no_value:    Just watch the address when there is a write */
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

        /* dr7 to be set for how watchpoint should be handled */
        if (write_dr(dr7, 7, pid) == -1)
                return -1;
        /* we might at somepoint want to extend this and replace it with num? */
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

int watch(char *buf, pid_t pid)
{
        uintptr_t addr;
        long word; /* so the value could be signed or unsigned. */
        int no_value = 0;

        /* check if there are any hw or sw breakpoint active atm */
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
                /* No argument is supplied by the user, display all set watchpoint
                 * address */
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
                /* if no argument is provided show all breakpoints currently set */
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

void help()
{
        char *help_str = "Commands supported.\n"
                "help:      This command.\n"
                "run:       run a (binary).\n"
                "attach:    Attach to (pid).\n"
                "detach:    Detach.\n"
                "write:     Write (value) to (addr).\n"
                "read:      Read from (addr).\n"
                "regs:      Get register value(s). [reg name] optional.\n"
                "step:      Go forward one instruction.\n"
                "continue:  Continue.\n"
                "break:     Set break point at (addr).\n"
                "break:     Show all breakpoints.\n"
                "delete:    Delete any software or hardware breakpoints or watchpoints.\n"
                "delete:    Delete breakpoint at (addr).\n"
                "delete:    Delete watchpoint at (addr).\n"
                "delete:    Delete hardware breakpoint at (addr).\n"
                "signal:    Set signal action to (pass) or (ignore).\n"
                "signal:    Show signal action.\n"
                "backtrace: Show backtrace.\n"
                "hardware:  Set Hardware breakpoint at (address).\n"
                "hardware:  Show all hardware breakpoints.\n"
                "watch:     Set watchpoint at (addr) for (value).\n"
                "watch:     Show all watchpoints.\n"
                "quit:      Exit from debugger.\n" ;

        printf("%s", help_str);
}

void exit_dbg(void)
{
        if(bp_list)
                rm_all_bp();
        clear_ds();
        tracee_pid = 0;
}

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
                        /* we need resumption because of signal delivery? */
                        if (resume_bp(bp, pid) == -1)
                                return -1;
                        bp->set = 0;
                }
        }
        /* remove any hardware breakpoints before leaving */
        if (hw_bp.set == 1)
                remove_hw(hw_bp.addr, pid);

        /* remove any hardware breakpoints before leaving */
        if (wp.set == 1)
                remove_wp(wp.addr, pid);

        if (detach(pid) == -1)
                return -1;

        exit_dbg();
        printf("Process detached\n");
        return 0;
}

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

/* Fork the binary, set PTRACEME and exec it. */
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

int run(char *buf)
{
        pid_t pid;
        int status;
        char *bin = strtok(NULL, " \n");
        if (bin == NULL)
                return -1;
        errno = 0;
        /* check if binary file even exists */
        status = access(bin, R_OK | X_OK);
        if (status == -1 || errno != 0) {
                fprintf(stderr, "Access error %s\n", strerror(errno));
                return -1;
        }
        fork_exec(bin);

        return 0;
}

/* handle SIGINT recieved by debugger. */
static void
int_handler(int sig, siginfo_t *siginfo, void *ucontext)
{
        if (sig == SIGINT)
                printf("Debugger interrupted\n");
        else
                fprintf(stderr, "This shouldn't be happening\n");
}

/* Register signal handler for debugger
 * NOTE: currently registered signals: SIGINT */
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
