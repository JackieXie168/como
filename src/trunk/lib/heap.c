/*
 * Copyright (c) 2004-2006, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the distribution.
 * * Neither the name of Intel Corporation nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

#include <stdlib.h>	/* malloc */
#include <string.h>	/* memset */
#include <inttypes.h>   /* uintN_t */
#include <errno.h>	/* error values */

#include "como.h"	/* safe_malloc, safe_realloc */
#include "heap.h"

/* 
 * this is defined here to hide it from other files.
 * other files just know the typedef (heap_t). 
 */
struct _heap_t {
    heap_compare cmp;			/* compare callback function */
    uint32_t size;			/* current heap size */
    uint32_t maxsize; 			/* heap max size. dynamic if set to 0 */
    uint32_t first_free;		/* first free element */
    void **array;			/* array with all elements */
};


heap_t *
heap_init(heap_compare cmp)
{
    heap_t *h;
    
    if (cmp == NULL) {
	/* callback compare() is mandatory */
	errno = EINVAL;
        return NULL;
    }
    
    h = (heap_t*) safe_malloc(sizeof(heap_t));
    h->cmp = cmp;
    h->size = 1;
    h->maxsize = 0; 		/* dynamic heap. no max size set */
    h->array = safe_malloc(h->size * sizeof(void*));
    h->first_free = 0; /* the heap is empty */
    
    return h;
}

#define _HEAP_LEFT(x)		(((x) << 1) + 1)
#define _HEAP_RIGHT(x)		(((x) << 1) + 2)
#define _HEAP_VALID_POS(x,max)	((x)<(max)?(x):0)
#define _HEAP_SWAP(a,b,tmp)	{tmp = a; a = b; b = tmp;}

#define HEAP_LEFT(h,x)		(_HEAP_VALID_POS(_HEAP_LEFT(x),h->first_free))
#define HEAP_RIGHT(h,x)		(_HEAP_VALID_POS(_HEAP_RIGHT(x),h->first_free))
#define HEAP_FATHER(x)		(((x) - 1) >> 1)
#define HEAP_SWAP(h,a,b,tmp)	_HEAP_SWAP(h->array[(a)],h->array[(b)],tmp)
#define HEAP_A_GT_B(h,a,b)	(h->cmp(h->array[(a)], h->array[(b)]))

/* 
 * -- heap_insert 
 * 
 * inserts a new element in the heap. if the heap is full tries to 
 * scale it up unless a fixed size is set. It returns 0 on success and 
 * a value errno in case of failure. 
 *
 */
int
heap_insert(heap_t *h, void *elem)
{
    /* first of all put the new element at the end */
    uint32_t curr = h->first_free;

    if (curr == h->size) {
	/* 
	 * heap is full. 
	 */
	if (h->maxsize == 0) { 
	    /* dynamic heap. double its size */
	    h->size <<= 1;
	    h->array = safe_realloc(h->array, h->size * sizeof(void*));
	} else { 
	    /* return an error and let the caller decide */
	    errno = ENOSPC; 
	    return errno; 
	}
    }
    
    /* restore the heap property */
    h->array[curr] = elem;
    h->first_free++;

    while (curr > 0) {
	void *tmp;
	uint32_t father = HEAP_FATHER(curr);
    
	if (HEAP_A_GT_B(h, father, curr))
	    break;
	
	HEAP_SWAP(h, curr, father, tmp);
	curr = father;
    }

    return 0;
}

int
heap_extract(heap_t *h, void **elem)
{
    uint32_t curr = 0;
    void *tmp;

    if (h->first_free == 0) {
	errno = ENOENT; 
	return errno;		/* heap is empty */
    }

    *elem = h->array[0];
    
    h->array[0] = NULL;
    HEAP_SWAP(h, 0, h->first_free - 1, tmp);
    h->first_free--;

    /*
     * LEFT and RIGHT should return 0 if > h->nelem
     */
    while (1) {
	uint32_t greatest, lson, rson;
	
	lson = HEAP_LEFT(h, curr);
	rson = HEAP_RIGHT(h, curr);

	if (lson == 0 && rson == 0) /* no more children */
	    break;

	if (lson == 0 || rson == 0)
	    greatest = lson + rson;
	else
	    greatest = HEAP_A_GT_B(h, lson, rson) ? lson : rson;
	    
	if (HEAP_A_GT_B(h, curr, greatest))
	    break;

	HEAP_SWAP(h, curr, greatest, tmp);
	curr = greatest;
    }

    return 0;
}

__inline__ void *
heap_root(heap_t *h)
{
    return h->first_free ? h->array[0] : NULL;
}

__inline__ void
heap_setsize(heap_t *h, int size) 
{ 
    h->maxsize = h->size = size; 
    h->array = safe_realloc(h->array, h->size * sizeof(void*));
}

void
heap_close(heap_t *h)
{
    if (h->size > 0)
	free(h->array);
    free(h);
}
