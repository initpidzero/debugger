/* this function is main debugger api, it can used by passing commands in buf */
int dbg(int *exit, char *buf);

/* this function can be used to test debugger by providing argc, argv command
 * line arguments */
int tester_fn(int *exit, int argc, char **argv);

/* this structure keeps track of breakpoint related data */
struct bp
{
    uintptr_t addr; /* address where break point is set */
    unsigned long word; /* content at breakpoint address */
    unsigned long trap; /* replacement for trap instruction on address */
    int set; /* 0 = bp is not set. 1 = bp is set.
              * 2 = breakpoint was hit and needs to be set again */
};

struct sig_dis
{
    int sig; /* signal recieved */
    int set; /* whether of not we have a pending signal */
    int act; /* 0 = signal is ignore. 1 = signal is passed to debuggee. */
};

/* we are only supporting one break point at this moment */
