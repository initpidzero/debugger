INC = .
CFLAGS = -g -I$(INC) -Wall -Wextra
TARGET = dbg sigsegv sigill sigfpe sigalarm toy
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
toy: test/toy.c
	$(CC) $(CFLAGS) -o $@ $<
clean:
	$(RM) $(TARGET) 
