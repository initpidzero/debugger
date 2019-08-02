INC = .
CFLAGS = -g -I$(INC) -Wall -Wextra
SFLAGS = -g -I$(INC) -Wall -Wextra -static
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
	$(CC) $(SFLAGS) -o $@ $<
clean:
	$(RM) $(TARGET) 
