INC = .
CFLAGS = -g -I$(INC) 
TARGET = dbg sigsegv sigill sigfpe sigalarm
OBJS = src/commands.c util/heap.c util/list.c
all: $(TARGET)
dbg: src/dbg.c
	$(CC) $(CFLAGS) -o $@ $(OBJS) $<
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
