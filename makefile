CFLAGS=-g 
TARGET = dbg sigsegv sigill sigfpe sigalarm
all: $(TARGET)
dbg: src/dbg.c
	$(CC) $(CFLAGS) -o $@ $<
sigsegv: test/sigsegv.c
	$(CC) $(CFLAGS) -o $@ $<
sigill: test/sigill.c
	$(CC) $(CFLAGS) -o $@ $<
sigfpe: test/sigfpe.c
	$(CC) $(CFLAGS) -o $@ $<
sigalarm: test/sigalarm.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	$(RM) $(TARGET) 
