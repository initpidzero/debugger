#include <stdio.h>
#include "list.h"

void list_init(struct list *list, void *element)
{
    list->element = element;
    list->next = NULL;
    list->prev = NULL;
    list->head = list;
}

/* add a pre allocated list member and a relevant element here */
void list_add_next(struct list **list, void *element, struct list *new)
{
    new->element = element;
    (*list)->next = new;
    new->prev = *list;
    new->head = (*list)->head;
    new->next = NULL;
    *list = new;
    printf("list %p list->prev %p new %p\n", list, (*list)->prev, new);
}

/* right so we want to find where in the list this element lies */
void *find_element(struct list *list, void *element)
{
    struct list *temp;
    for(temp = list->head; temp!= NULL; temp = temp->next) {
        if (temp->element == element)
            return temp;
    }
    return NULL;
}
