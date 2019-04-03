#ifndef __HEAP_H__
#define __HEAP_H__

/* Get a size chunk of memory from heap. */
void *get_mem(size_t size);

/* Return memory back to heap */
void rm_mem(void *mem);

#endif
