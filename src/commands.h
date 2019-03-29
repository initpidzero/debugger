#ifndef __DBG_HELPER_H__
#define __DBG_HELPER_H__

/* Spawn the binary with PTRACE_TRACEME. */
int run(char *buf);

/* Attach the process with pid */
int pattach(pid_t pid);

/* prints help */
void help();

/* Handle breakpoint command.
 * Extract address for break point.
 * Check if breakpoint at this address is active.
 * if not, sets breakpoint on user provided address.
 * if address is not provided, display the currently set breakpoints. */
int breakpoint(char *buf, pid_t pid);

/* Handle hardware breakpoint command.
 * Extract address for break point
 * Check if hardware breakpoint at this address is active
 * if not, sets breakpoint on user provided address
 * if address is not provided, display the currently set breakpoints. */
int hw(char *buf, pid_t pid);

/* Set signal action for signals from debuggee.
 * Signals can either be ignored(default action)
 * or passed on to debuggee on next ptrace running command.
 */
int p_sig(char *buf, pid_t pid);

/* Obtain backtrace from current point.
 * The implementation is still a bit shaky.
 * we only unwind the stack upto two levels.*/
int bt(pid_t pid);

/* Delete breakpoint(hardware or software) or watchpoint.
 * If address is provided, then particular breakpoint is deleted else all
 * breakpoints are delete.
 * Currently, only one hardware breakpoint and one watchpoint can be set, so
 * address for hw bp and wp are not used. */
int delete(char *buf, pid_t pid);

/* Handle continue command.
 * This function decides continuation based on
 * type of breakpoint or watchpoint set.
 */
int cont(pid_t pid);

/* Handle single stepping command */
int step_bp(pid_t pid);

/* This function is called when user enters write command.
 * It parses arguments for write command to find which address
 * value user want to write at and what content user want to write */
int p_poke(char *buf, pid_t pid);

/* This function is called when user enters read command.
 * It parses arguments for read command to find which address
 * value user want read */
int p_peek(char *buf, pid_t pid);

/* This function is called when user enters regs command.
 * It parses arguments for regs command to find which register's
 * value user want to see */
int regs(char *buf, pid_t pid);

/* This function is ptrace detach*/
/* It also checks for any signals which needs to delivered */
int pdetach(pid_t pid);

/* initialise some variables */
void init_dbg();

/* This function is called when user sends watch command
 * It obtains addr for watchpoint
 * Checks if breakpoints(hw or sw) are set
 * sets watchpoint on a give addr for a particular value */
int watch(char *buf, pid_t pid);

#endif
