/* This program should be able to use basic ptrace functionality to provide
 * debugging facilities.
 * Commands supported can be seen in commands string array.
 * This file contains :
 * 1. Main function.
 * 2. Tester function.
 * 3. Command loop.
 * 4. Command parsing.
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


/* This is debuggee pid */
int tracee_pid =  0;

/* Each command is given an index, which makes it easier to
 * maintain switch case for various commands */
enum {
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
        p_hw,
        p_watch,
        p_quit
};

/* Corresponding command string for each command.
 * We want to index commands wrt enumerator above.  */
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
        "hardware",
        "watch",
        "quit"
};

/* Convert Token string into command index */
static int command_to_execute(char *token)
{
        int i;
        for (i = 0; i < p_quit + 1; i++) {
                if (strncmp(commands[i], token, strlen(commands[i]))==0)
                        return i;
        }
        return -1;
}

/* Tokenise first string from buf until a blank space is found */
static char *tokenise(char *buf)
{
        return strtok(buf, " ");
}

/* Extract pid from attach command.
*/
static pid_t extract_pid(char *buf)
{
        pid_t pid;
        char *temp = strtok(NULL, " \n");
        if (temp == NULL)
                return -1;
        pid = strtoul(temp, NULL, 10);
        return pid;
}

/* Main debugger api driving the debugger.
 * exit: 0 = quit, 1 = continue.
 * buf: commands and parameters in form of \n terminated line
 */
int dbg(int *exit, char *buf)
{
        int com = 0;
        char *token  = NULL;

        token = tokenise(buf);
        if (token == NULL)
                fprintf(stderr, "strtok failed : %s\n", strerror(errno));

        /* convert command into index */
        com = command_to_execute(token);
        switch (com) {
        case p_help:
                help();
                break;

        case p_run:
                if (run(buf) == -1)
                        fprintf(stderr, "Cannot run this binary\n");
                break;

        case p_attach:
                /* If tracee_pid is not valid, debuggee cannot be attached */
                tracee_pid = extract_pid(buf);
                if (tracee_pid == -1) {
                        fprintf(stderr, "No pid specified\n");
                        tracee_pid = 0;
                }  else if (tracee_pid == 0) {
                        fprintf(stderr, "unable to extract pid\n");
                } else {
                        if (pattach(tracee_pid) == -1)
                                fprintf(stderr, "attach failed\n");
                }
                break;

        case p_detach:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }

                if (pdetach(tracee_pid) == -1)
                        fprintf(stderr, "detach failed\n");
                else
                        tracee_pid = 0;
                break;

        case p_write:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (p_poke(buf, tracee_pid) == -1)
                        fprintf(stderr, "unable to write\n");
                break;

        case p_read:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (p_peek(buf, tracee_pid) == -1)
                        fprintf(stderr, "unable to read\n");
                break;

        case p_regs:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (regs(buf, tracee_pid) == -1)
                        fprintf(stderr, "unable to get register values\n");
                break;

        case p_cont:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (cont(tracee_pid) == -1)
                        fprintf(stderr, "unable to continue\n");
                break;

        case p_step:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (step_bp(tracee_pid) == -1)
                        fprintf(stderr, "unable to step\n");
                break;

        case p_break:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (breakpoint(buf, tracee_pid) == -1)
                        fprintf(stderr, "Breakpoint couldn't be set\n");
                break;

        case p_delete:
                if (delete(buf, tracee_pid) == -1)
                        fprintf(stderr, "Cannot delete breakpoint \n");
                break;

        case p_signal:
                if (p_sig(buf, tracee_pid) == -1)
                        fprintf(stderr, "Cannot set signal action \n");
                break;

        case p_bt:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (bt(tracee_pid) == -1)
                        fprintf(stderr, "Cannot get backtrace \n");
                break;

        case p_hw:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (hw(buf, tracee_pid) == -1)
                        fprintf(stderr, "Cannot set hardware breakpoint \n");
                break;

        case p_watch:
                if (tracee_pid == 0) {
                        fprintf(stderr, "No debuggee found\n");
                        break;
                }
                if (watch(buf, tracee_pid) == -1)
                        fprintf(stderr, "Cannot set watchpoint \n");
                break;

        case p_quit:
                /* exit clean by detaching before quiting */
                if (tracee_pid != 0)
                        if (pdetach(tracee_pid) == -1)
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
        for (i = 1; i < argc || exit == 0; i++)
                dbg(exit, argv[i]);

        return 0;
}

int main (int argc, char **argv)
{
        int exit = 1; /* The value is changed to zero when user calls quit command */
        char prompt[] = "(dbg):";
        char buf[BUFSIZE];

        /* Do some initialisation. */
        init_dbg();
        /* this is to carry out testing */
        if (argc > 1)
                return tester_fn(&exit, argc, argv);

        while (exit) {
                ssize_t bytes_read;

                errno = 0;
                if (write(STDOUT_FILENO, prompt, strlen(prompt) + 1) == -1 || errno != 0)
                        fprintf(stderr, "write failed : %s\n", strerror(errno));

                bzero(buf, BUFSIZE);
                errno = 0;
                bytes_read = read(STDIN_FILENO, buf, BUFSIZE);
                if (bytes_read == -1 || errno != 0)
                        fprintf(stderr, "read failed : %s\n", strerror(errno));
                assert(bytes_read > 0);

                dbg(&exit, buf);
        }
        return 0;
}
