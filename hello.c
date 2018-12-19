#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main (void)
{
    unsigned long i = 0;
    pid_t pid = getpid();
    char hello[] = "hello world";
    int len = strlen(hello);

    for(; i < 4294900; i++ )
    {
        unsigned long j = 0xfedcba9876543210;
        printf("%s %d %p  i = %lx &i = %p\n", hello, pid, hello, i, &i);
        printf("j = %lx &j = %p\n", j, &j);
        if(i == 0)
            getchar();
    }
    return 0;
}
