#include <stdio.h>
int main(void)
{
    char regs [][8] = {"regs", "regs", "rags"};
    printf("%d\n", sizeof(regs)/sizeof(regs[0]));
    return 0;
}
