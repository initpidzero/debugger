#include <stdio.h>
#include <unistd.h>
#include <string.h>

char hello[] = "hello world";

int main (void)
{
    unsigned long i = 0;
    pid_t pid = getpid();

    for(; i < 40000; i++ )
    {
        printf("%s %d %p  i = %lx &i = %p\n", hello, pid, hello, i, &i);
    }
    return 0;
}
