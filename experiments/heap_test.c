#include <stdio.h>
#include <stdint.h>
#include "../util/list.h"
#include "../util/heap.h"
#include "../src/dbg.h"

int main(void)
{
    size_t size =  sizeof(struct bp);

    for(int i = 0; i < 50; i++)
    {
        uintptr_t *temp = get_mem(size*4);
        printf("%p, \n", temp);
    }

    return 0;
}
