#ifndef __LIST_H__
#define __LIST_H__

/* list data structure */
struct list {
        void *element;
        struct list *next;
        struct list *prev;
        struct list *head;
};

/* initiate list with element */
void list_init(struct list *list, void *element);

/* get number of elements in this list */
unsigned int get_num_members(struct list *list);

/* add another member to the list, "new" with value as "element" */
void list_add_next(struct list **list, void *element, struct list *new);

/* find the head of the list for this given element */
void *find_element(struct list *list, void *element);

/* remove this node from the list */
void *list_del_node(struct list **list, struct list *node);
#endif
