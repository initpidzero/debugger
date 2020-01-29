/* A crude implementation of doubly linked list */
#include <stdio.h>
#include "list.h"

void list_init(struct list *list, void *element)
{
        /* so the list embeds element as part of data structure */
        if (list == NULL) {
                fprintf(stderr, "List is empty\n");
                return;
        }
        list->element = element;
        list->next = NULL;
        list->prev = NULL;
}

unsigned int get_num_members(struct list *list)
{
        int num = 0;
        struct list *temp = NULL;

        if (list == NULL) {
                return num;
        }

        for (temp = list; temp != NULL; temp = temp->next) {
                num++;
        }

        return num;
}

void list_add_next(struct list **list, void *element, struct list *new)
{
        if (list == NULL) {
                fprintf(stderr, "List is empty\n");
                return;
        }

        /* list moves on, since the head is embedded in list */
        new->element = element;
        (*list)->next = new;
        new->prev = *list;
        new->next = NULL;
        *list = new;
        printf("list %p list->prev %p new %p\n", *list, (*list)->prev, new);
}

void *find_element(struct list *list, void *element)
{
        struct list *temp;

        if (list == NULL) {
                fprintf(stderr, "List is empty\n");
                return NULL;
        }

        for (temp = list; temp != NULL; temp = temp->next) {
                if (temp->element == element)
                        return temp;
        }
        return NULL;
}

void *list_del_node(struct list **list, struct list *node)
{
        struct list *temp;
        for (temp = *list; temp != NULL; temp = temp->next) {
                if (temp == node) {
                        temp->prev->next = node->next;
                        temp->next->prev = node->prev;
                }
        }
        return NULL;
}
