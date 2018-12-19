CFLAGS=-g 
all: dbg sigsegv sigill sigfpe sigalarm
dbg: dbg.c
	$(CC) $(CFLAGS) -o $@ $<
sigsegv: sigsegv.c
	$(CC) $(CFLAGS) -o $@ $<
sigill: sigill.c
	$(CC) $(CFLAGS) -o $@ $<
sigfpe: sigfpe.c
	$(CC) $(CFLAGS) -o $@ $<
sigalarm: sigalarm.c
	$(CC) $(CFLAGS) -o $@ $<
