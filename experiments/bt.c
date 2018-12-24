/* c file for nested function for traces */
#include <stdio.h>

static int fn3()
{
    printf("deepest level \n");
    return 0;
}


static int fn2()
{
    fn3();
    return 0;
}

static int fn1()
{
    fn2();
    return 0;
}

int main(void)
{
    fn1();
    return 0;
}
