#include <stdio.h>
#include <stdint.h>
#include "../util/list.h"
#include "../util/heap.h"
#include "../src/dbg.h"

int main(void)
{
    size_t size =  sizeof(struct bp);

    int i;
    for(i = 0; i < 100; i++)
    {
        int j = (i % 5)? (i % 5) : 1;
        uintptr_t *temp = get_mem(size * j);
        printf(" %d %p \n",size * j, temp);
    }

    return 0;
}
