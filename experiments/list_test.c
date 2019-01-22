#include <stdio.h>
#include <stdint.h>
#include "list.h"
#include "src/dbg.h"

struct test
{
    int i;
    char c;
};

int main(void)
{
    struct test test;
    struct list *list;
    struct list head;
    int i = 0;

    test.i = 10;
    test.c = 'a';

    list_init(&head, &test);
    list = &head;
    struct list local[5];
    struct test element[5];
    printf("%d\n", sizeof(struct bp));
    for(; i < 5; i++)
    {
        element[i].i = i;
        element[i].c = 'a' + i;
        printf("%p, %p, %p\n", list, &element[i], &local[i]);
        list_add_next(&list, &element[i], &local[i]);
    }

    for(struct list *temp = &head; temp != NULL; temp = temp->next)
    {
        printf("temp = %p\n", &temp);
        printf("%d\n",((struct test *)temp->element)->i);
        printf("%c\n",((struct test *)temp->element)->c);
        printf("%p\n",temp->head);
    }
    return 0;
}
