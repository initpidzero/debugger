#include <stdio.h>
#include <stdint.h>
#include "../util/list.h"
#include "../src/dbg.h"

struct test
{
        int i;
        char c;
};

int populate_element(struct test *element, int i, char c)
{
        element->i = i;
        element->c = c;
}

void print_list(struct list *list)
{
        for (struct list *temp = list; temp != NULL; temp = temp->next) {
                //       printf("temp = %p\n", &temp);
                printf("i = %d\n",((struct test *)temp->element)->i);
                printf("c = %c\n",((struct test *)temp->element)->c);
                //        printf("%p\n",temp->head);
        }

}

int main(void)
{
        struct test test;
        struct list *list;
        struct list head;
        struct list *del;
        int i = 0;

        populate_element(&test, -1, 'z');

        list_init(&head, &test);
        list = &head;
        struct list local[5];
        struct test element[5];
        // printf("%d\n", sizeof(struct bp));
        for (; i < 5; i++) {
                populate_element(&element[i], i, 'a' + i);
                //printf("%p, %p, %p\n", list, &element[i], &local[i]);
                list_add_next(&list, &element[i], &local[i]);
                if ( i == 3)
                        del = list;

        }

        print_list(&head);

        printf("after deletion\n");
        list_del_node(&head, del);
        print_list(&head);
        del = (struct list *)get_head(list);
        printf("head = %d head = %d\n", ((struct test *)head.element)->i,
               ((struct test *)del->element)->i);
    return 0;
}
