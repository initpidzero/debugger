#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>

static int check_for_eos(char *byte)
{
    int len = sizeof(long);
    int i = 0;
    for(;i < len; i++)
    {
        printf("%c", byte[i]);
        if(byte[i] == 0)
            return i;
    }
    return -1;
}

void rev(char *str, int len)
{
    char temp;
    int i = 0;
    for(i = 0; i < len/2; i++){
        temp = str[i];
        str[i] = str[len - i];
        str[len] = temp;
        putchar(str[i]);
    }
    printf("did this reverse %s\n", str);
}


int main (int argc, char **argv)
{
    pid_t pid;
    struct user_regs_struct regs;
    intptr_t addr;
    int status;
    int  long_size = sizeof(long);
    union data {
        long word;
        char bytes[long_size];
    };

    sscanf(argv[1], "%lu", &pid);
    sscanf(argv[2], "%"SCNxPTR"", &addr);
    printf("%"PRIxPTR"\n", addr);
    char *ptr = (char *)addr;
    printf("%lu\n", pid);
    status = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if(status != 0)
        fprintf(stderr,"%s\n", strerror(errno));

    printf("attached\n");

    status = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    if(status != 0)
        fprintf(stderr,"%s\n", strerror(errno));

    int i = 0;
    int j =0;
    while(i < 10) {
        union data array[2];

        long long int orig_rax = ptrace(PTRACE_PEEKUSER, pid, ORIG_RAX * 8, NULL);
        if(errno == 0)
            printf("%llx\n", orig_rax);
        status = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if(status != 0) {
            fprintf(stderr,"%s\n", strerror(errno));
        } else {
            printf("orig_rax = %lld rdi = %llx, rsi = %lld rdx = %llx, rax = %llx\n",
                   regs.orig_rax, regs.rdi, regs.rsi, regs.rdx, regs.rax);
        }
        array[j].word = ptrace(PTRACE_PEEKDATA, pid,  ptr + j * long_size, NULL);

        if(errno == 0) {
            printf("%lx\n", array[j].word);
            /*char *tmp = (char *)&(array[i].word);
            printf("%s", array[i].bytes);
            for(size_t j = 0; j < long_size; j++)
                printf("%lx", (unsigned long)*(tmp + j)); */
            int pos = check_for_eos(array[j].bytes);
            if(pos == -1)
            {
               j++;
            }
            else
            {
                printf("\nposition = %d\n", pos);
                int str_len = j * long_size + pos + 1;
                printf("strlen = %d\n", str_len);
                char str[str_len];
                memcpy(str, array[0].bytes, long_size);
                memcpy(str + long_size, array[1].bytes, str_len - long_size);

                printf("\nfull string = %s\n", str);
                j = 0;
                bzero(array, sizeof(array));
            }
        }
        sleep(1);
        i++;
    }
    union data data;
    strcpy(data.bytes , "goodbye");
    ptrace(PTRACE_POKEDATA, pid,  ptr, data.word);
    getchar();
    status = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if(status != 0)
        fprintf(stderr,"%s\n", strerror(errno));
    printf("detached\n");

    return 0;
}
