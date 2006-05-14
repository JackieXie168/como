/*
 * Copyright (c) 2005 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#ifndef _COMO_HEAP_H
#define _COMO_HEAP_H

/*
 * This is a general purpose heap/priority queue implementation.
 */

/*
 * heap_compare() callback
 * This callback is used by the heap to compare two elements; should return
 * a value > 0 if a > b.
 * This callback is mandatory.
 */
typedef int (*heap_compare) (const void *a, const void *b);

/*
 * The opaque heap_t size.
 */
typedef struct _heap_t heap_t;

/*
 * heap_init()
 * Initializes a heap.
 *
 * cmp		- the callback used to compare any two elements 
 *
 * Return a pointer to an initialized heap handle, or NULL on failure.
 */
heap_t*
heap_init(heap_compare cmp);

/*
 * heap_insert()
 * Insert the element pointed by elem in the heap.
 * Please note that the heap stores only the pointer to your data, please
 * ensure that it remains valid throughout the heap's life.
 *
 * Returns 0 on success, -1 on failure (heap full and/or resize failed)
 */
int
heap_insert(heap_t *h, void *elem);

/*
 * heap_extract()
 * Extract an element (that is, the element with the highest priority
 * according to the heap_compare() callback) and fill elem with a pointer
 * to it.
 *
 * Return 0 on success, -1 if the heap is empty.
 */
int
heap_extract(heap_t *h, void **elem);

/*
 * heap_root()
 * Return the pointer conatined in the root node (the element with highest
 * priority, *without actually extracting* it from the heap.
 * Return NULL if the heap is empty.
 */
void *
heap_root(heap_t *h);

/*
 * heap_close()
 * Frees the resources allocated by the heap and the heap handler itself.
 */
void
heap_close(heap_t *h);

/*
 * heap_maxsize(heap_t *h, int size)
 * Sets the maximum size of the heap. If size = 0, the heap will 
 * grow to fit all elements. By default size is set to 0. 
 */
void
heap_setsize(heap_t *h, int size);

#endif /* _COMO_HEAP_H */
