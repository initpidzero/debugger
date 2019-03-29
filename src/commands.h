#ifndef __DBG_HELPER_H__
#define __DBG_HELPER_H__

/* spawn the binary with debugger */
int run(char *buf);

/* attach the process with pid */
int pattach(pid_t pid);

/* prints help */
void help();

/* This function is called when user sends breakpoint command
 * It obtains addr for break point
 * Checks if breakpoint at this address is active
 * sets breakpoint on user provided address */
int breakpoint(char *buf, pid_t pid);

/* This function is called when user sends hardware command
 * It obtains addr for break point
 * Checks if breakpoint at this address is active
 * sets breakpoint on user provided address */
int hw(char *buf, pid_t pid);

/* This function set the action for signals from debuggee
 */
int p_sig(char *buf, pid_t pid);

/* get back trace
 * let's do it for 5 levels */
int bt(pid_t pid);

/* This function is called when user sends delete command
 * It removes the break point or tells user if there is no
 * breakpoints currently active */
int delete(char *buf, pid_t pid);

/* This is main continue function.
 * pid process id for debuggee
 * Do we allow both software and hardware breakpoint at the same time?
 * Let's assume here that only one type of breakpoint is set:
 * Each of them have their own function.
 */
int cont(pid_t pid);

/* Main stepping function checks for break points */
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
