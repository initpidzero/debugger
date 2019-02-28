#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "list.h"

#define MAX_PAGES 20

static struct list heap_start;
static struct list *heap = NULL;
static size_t page_size = 0;

struct map {
    uintptr_t *current; /* this current free location in map */
    size_t free;
};

struct map current;

/* mmap one page*/
/* if mmap fails ,return NULL */
uintptr_t *page(uintptr_t *start)
{
    errno = 0;
    uintptr_t *map = mmap(start, page_size, PROT_READ | PROT_WRITE ,
                          MAP_ANONYMOUS | MAP_PRIVATE| MAP_FIXED, -1, 0);
    if (map == MAP_FAILED || errno != 0) {
        fprintf(stderr, "Mmap error %s\n", strerror(errno));
        return NULL;
    }

    return map;
}

/* unmap this page */
void unpage(uintptr_t *page)
{
    munmap(page, page_size);
}

/* initilise the heap */
int heap_init()
{
    uintptr_t *map_start = NULL;
    page_size = getpagesize();
    errno = 0;
    map_start = mmap(NULL, page_size, PROT_READ | PROT_WRITE ,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (map_start == MAP_FAILED || errno != 0) {
        fprintf(stderr, "Mmap error %s\n", strerror(errno));
        return -1;
    }
    list_init(&heap_start, map_start);
    heap = &heap_start;

    //printf("map begins at %p \n",  heap->element);
    current.current = heap->element;
    current.free = page_size;
}

/* so we can't just add elements to the list without either allocation
 * or static list of array.
 *
 */
int add_page()
{
    static struct list list[MAX_PAGES];
    static int i = 0;
    uintptr_t *begin = heap->element + page_size;
    if (i < MAX_PAGES) {
        uintptr_t *map = page(begin);
        list_add_next(&heap, map, &list[i]);
        i++;
    //    printf("map next at %p \n",  heap->element);
        return 0;
    } else {
        return -1;
    }
}

/* 1. I want to have some sort of start index
 * 2. I want to have some sort of link list to keep track of all pages
 * 3. I want to give certain amount of memory to allocated, pointer moved for
 * current memory.
 * */
int manage_heap()
{
    if(NULL == heap)
        heap_init();
    else
        add_page();
}

/* Get a size chunk of memory */
void *get_mem(size_t size)
{
    assert(size <= 256);
    size_t chunk;
    uintptr_t *prev;

    /* we would want to allocate memory in chunks of 2^x */
    /* find closest memory boundary */
    /* find first free space */
    /* move memory location to next free boundary */
    /* if we don't have free space in page, allocate another page */
    if(size <= 16)
        chunk = 16;
    else if(size <= 32)
        chunk = 32;
    else if(size <= 64)
        chunk = 64;
    else if(size <= 128)
        chunk = 128;
    else
        chunk = 256;

    if(heap == NULL)
        heap_init();

    //printf("Free mem = %lu\n", current.free);
    if(current.free >= chunk) {
        prev = current.current;
        current.current = (uintptr_t *)((uintptr_t)current.current + chunk);
        current.free = current.free - chunk;
    } else {
        size_t more = chunk - current.free;
        add_page();
        prev = current.current;
        current.current = (uintptr_t *)((uintptr_t)heap->element + more);
        current.free = page_size - more;
    }

    return prev;
}

void rm_mem(void *mem)
{
    /* we need a way to make memory unavailable for usage */
}

/* unmap all memory */
void rm_all_map()
{
    struct list *temp;
    for (temp = heap->head; temp!= NULL; temp = temp->next) {
        unpage(temp->element);
    }
}
