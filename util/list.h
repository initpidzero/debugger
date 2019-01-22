#ifndef __LIST_H__
#define __LIST_H__
struct list
{
    void *element;
    struct list *next;
    struct list *prev;
    struct list *head;
};

void list_init(struct list *list, void *element);

void list_add_next(struct list **list, void *element, struct list *new);


void *find_element(struct list *list, void *element);

#endif
