#ifndef __LIST_H__
#define __LIST_H__
struct list {
    void *element;
    struct list *next;
    struct list *prev;
    struct list *head;
};

/* initiate list with element */
void list_init(struct list *list, void *element);

/* add another member to the list, "new" with value as "element" */
void list_add_next(struct list **list, void *element, struct list *new);

/* find the head of the list for this given element */
void *find_element(struct list *list, void *element);

#endif
