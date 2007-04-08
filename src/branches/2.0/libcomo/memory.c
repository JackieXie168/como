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

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>

#include <stdio.h>
#include <sys/time.h>

#define LOG_DOMAIN "MEMORY"
#define LOG_DISABLE
#include "como.h"
#include "comopriv.h"


/*
 *

--- ARCHITECTURE ---

The memory allocator manages chunks of memory of variable size,
each described by a 'memblock_t'. 'size' contains
the size of the user-portion (data[]) of the block, while
'next' is used to build free lists of blocks, typically of the same size.

Each list is reachable through a 'memmap_t' structure, which
normally contains a pointer to the head of the list, the size
of each entry, and the number of entries in the list.

A memory map is made of an array of such memmap_t's.
Entry #0 is special and used as follows:
  size	is the number of entries in the array;
  count	is the index of the first free entry;
  next	is a pointer to a list of blocks that could not
	fit in the arrays otherwise.
	THE BLOCKS IN THIS LIST MAY HAVE DIFFERENT SIZES.
Entries #1 .. #count-1 contain non-empty lists.
Entries #count .. #size-1 are empty.

The memory allocator functions uses a map as the first parameter that
contains information about the free blocks. The maps cannot be reallocated, 
so when they run out of slots to keep free blocks it is necessary to store 
elements in entry #0, unsorted.  All allocations are done from maps, and 
presumably in a shared memory segment.

 *
 */

#define MIN_SIZE	32	/* do not split less than this */

typedef struct memblock memblock_t;

struct memblock {
    memblock_t *	next;
    void *		_magic;
#define	MY_MAGIC	(void *)0x91919191
#define	MY_MAGIC_IN_USE	(void *)0x50b50b
    size_t		size;	/* actual size of data[] */
    uint8_t		data[0];
};


/*
 * Entries of a memmap.
 */
struct memmap {
    memblock_t *	next;
    size_t		size;	/* user data size */
    uint32_t		count;	/* elements in this list */
#define overflow_list(x)	(x)[0].next
#define	map_size(x)		(x)[0].size
#define	first_free(x)		(x)[0].count
};

typedef struct memmap_state {
    void *	low;	/* min allowed shared addresses */
    void *	high;	/* max allowed shared addresses */
    size_t	usage;	/* used memory */
    size_t	peak;	/* peak usage */
    memmap_t	map[0];
} memmap_state_t;


/* 
 * -- check_memblock
 * 
 * checks that a block is within the shared memory 
 * region. panics otherwise. 
 * 
 */
static inline void 
check_memblock(memmap_state_t * mem, memblock_t * x) 
{
    void *c = (void *)x;		

    if (c < mem->low || c >= mem->high)
	error("corrupted ptr %p: out of boundaries %p...%p\n", 
	      x, mem->low, mem->high);

    if ((x)->_magic != MY_MAGIC && (x)->_magic != MY_MAGIC_IN_USE)
	error("corrupted ptr %p: bad magic value\n",
	      x, (x)->_magic, MY_MAGIC);	
}


static inline memmap_state_t *
memmap_get_state(memmap_t * m)
{
    return ((memmap_state_t *) m) - 1;
}


/*
 * Insert block x into the map m
 */
static void
memmap_insert(memmap_t * m, memblock_t * x)
{
    uint32_t i;
    memmap_state_t *mem;
    
    mem = memmap_get_state(m);

    check_memblock(mem, x); 

    debug("memmap_insert %p size %8d, map %p %2d/%2d\n",
	  x, x->size, m, first_free(m), map_size(m));

    for (i = 1; i < first_free(m); i++) 
	if (m[i].size == x->size)	/* found the slot */
	    break;
    if (i >= map_size(m)) {		/* We ran out of slots */
	warn("Full map: using overflow list\n");
	x->next = overflow_list(m);
	overflow_list(m) = x;
	return;
    }
    if (i > first_free(m))
	error("invalid memmap_insert index %d should be %d max %d\n",
		i, first_free(m), map_size(m));
    if (i == first_free(m)) {		/* Previously empty slot */
	first_free(m)++;
	m[i].next = NULL;
	m[i].size = x->size;
	m[i].count = 0;
    }
    x->next = m[i].next;
    m[i].count++;
    m[i].next = x;
}


/* 
 * -- memmap_malloc()
 * 
 * this function allocates a new block of the memory from the 
 * free list. It looks into the lists (memmap_t) to find a block
 * whose size is equal to the requested size or the smallest 
 * block that would fit the size. In the case the size is not 
 * exactly the same it will split the block and insert the new
 * smaller one in a different list.
 * 
 */
static void *
memmap_malloc(size_t size, UNUSED const char * file, UNUSED int line,
              memmap_t * m)
{
    uint32_t i, cand;
    memblock_t *x;
    memmap_state_t *mem;
    
    assert(m != NULL);
    
    mem = memmap_get_state(m);

    debug("memmap_malloc %4d in_use %6d/%6d (map %p %2d/%2d)\n",
	size, mem->usage, mem->peak, m, first_free(m),
        map_size(m));

    cand = 0; 
    i = 1; 
    while (i < first_free(m)) { 
	/*debug("slot %2d size %8d count %3d p %p\n",
		i, m[i].size, m[i].count, m[i].next);*/
	if (m[i].next == NULL) {	/* empty slot, grab the last one */
	    first_free(m)--;
	    m[i] = m[first_free(m)];
	    continue;
	}
	if (m[i].size == size) {		/* found it */
	    cand = i;
	    break;
	}
	if (m[i].size > size) {		/* potential candidate */
	    if (cand == 0 || m[i].size < m[cand].size)
		cand = i;
	}
	i++;
    }
    if (cand == 0) {
	warn("out of memory for %d bytes (%s:%d)!\n", size,
	     file, line);
	for (i = 1; i < first_free(m); i++) {
	    debug("  . slot %2d size %8d count %3d p %p\n",
		i, m[i].size, m[i].count, m[i].next);
	}
	return NULL;
    }

    debug("new_mem need %d have %d at slot %d\n", 
	  size, m[cand].size, cand);

    /* we have got a memory block update the memory map */
    x = m[cand].next;
    check_memblock(mem, x); 
    m[cand].count--;
    m[cand].next = x->next;
    x->next = NULL;
    if (m[cand].next == NULL) {	/* slot now empty, replace with last one */
	first_free(m)--;
	m[cand] = m[first_free(m)];
    } else if (cand != 1) {	/* move to front. */
	memmap_t y = m[cand];
	m[cand] = m[1];
	m[1] = y;
    }
    if (x->size - size > MIN_SIZE + sizeof(memblock_t)) {
	/* split the block */
	memblock_t *y = (memblock_t *)(x->data + size);

	y->size = x->size - size - sizeof(memblock_t);
	y->_magic = MY_MAGIC;
	x->size = size; /* FIXME: padding? */
	memmap_insert(m, y);
    }

    mem->usage += x->size;
    if (mem->usage > mem->peak)
	mem->peak = mem->usage;

    x->_magic = MY_MAGIC_IN_USE;

    return x->data;
}


/*
 * -- memmap_free
 * 
 * Frees the block of memory p into pool m. If a non-zero size is 
 * specified, the size is also checked with the allocation.
 * 
 */
static void
memmap_free(void * p, UNUSED const char * file, UNUSED int line, memmap_t * m)
{
    memblock_t *x;
    memmap_state_t *mem;
    
    assert(m != NULL);

    if (p == NULL)
	return;
    
    mem = memmap_get_state(m);

    x = (memblock_t *) p - 1;
    check_memblock(mem, x);
    
    if (x->_magic != MY_MAGIC_IN_USE) {
	error("block not in use, %p magic %p (%s:%d)\n", x, x->_magic,
	      file, line);
    }
    x->_magic = MY_MAGIC;
    debug("mfree_mem %p size %d\n", p, x->size);

    mem->usage -= x->size;

    memmap_insert(m, x);
}


/* 
 * -- memmap_create
 * 
 * creates a new shared memory segment and initializes a memory map.
 * 
 */
memmap_t *
memmap_create(shmem_t * shmem, uint32_t entries)
{
    void *x;
    memmap_state_t *mem;
    memmap_t *map;
    memblock_t *m;
    size_t ctrl;
    size_t size;

    /*
     * we put the memmap state structure at the beginning of the
     * chunk, followed by the memory block that contains the actual
     * allocated space.
     */    
    x = shmem_baseaddr(shmem);
    size = shmem_size(shmem);
    
    /* size of control structures */
    ctrl = sizeof(memmap_state_t) + (sizeof(memmap_t) * (1 + entries));
    
    memset(x, 0, ctrl);

    mem = (memmap_state_t *) x;
    x += sizeof(memmap_state_t);
    
    map = &mem->map[0];
    
    x += sizeof(memmap_t) * (1 + entries);
    
    /* initially the map has only a big block */
    m = (memblock_t *) x;
    m->size = size - ctrl - sizeof(memblock_t);
    m->_magic = MY_MAGIC;
    m->next = NULL;
    
    mem->low = mem->high = (void *) m;
    mem->high += size - ctrl;

    /* create an initial, pseudo-empty map */
    map_size(map) = entries;
    first_free(map) = 1;
    overflow_list(map) = NULL;
    memmap_insert(map, m);
    
    return map;
}


memmap_stats_t *
memmap_stats_location(memmap_t * m)
{
    memmap_state_t *mem;
    mem = memmap_get_state(m);
    return (memmap_stats_t *) &mem->usage;
}


size_t
memmap_usage(memmap_t * m)
{
    memmap_state_t *mem;
    mem = memmap_get_state(m);
    return mem->usage;
}


size_t
memmap_peak(memmap_t * m)
{
    memmap_state_t *mem;
    mem = memmap_get_state(m);
    return mem->peak;
}


static void *
memmap_calloc(size_t nmemb, size_t size, const char * file, int line,
	      memmap_t * m)
{
    void *ptr;
    
    size *= nmemb;
    ptr = memmap_malloc(size, file, line, m);
    /* XXX check if out of memory */
    memset(ptr, 0, size);
    return ptr;
}


void
memmap_alc_init(memmap_t * m, alc_t * alc)
{
    alc->malloc = (alc_malloc_fn) memmap_malloc;
    alc->calloc = (alc_calloc_fn) memmap_calloc;
    alc->free = (alc_free_fn) memmap_free;
    alc->data = m;
}

#if 0

#define ALLOCS 10000

int
main(int argc, char **argv)
{
    memmap_t *m;
    alc_t alc;
    int i;
    void *p[ALLOCS];
    
    struct timeval t1, t2;
    uint64_t d1, d2;
    double imp;
    
    m = memmap_create(64, 1024);
    
    memmap_alc_init(m, &alc);
    
    gettimeofday(&t1, NULL);
    
    for (i = 1; i < ALLOCS; i++) {
	p[i] = alc_malloc(&alc, i * 4);
    }
    for (i = 1; i < ALLOCS; i++) {
	alc_free(&alc, p[i]);
    }
    for (i = 1; i < ALLOCS; i++) {
	p[i] = alc_malloc(&alc, i * 2);
    }
    for (i = 1; i < ALLOCS; i++) {
	alc_free(&alc, p[i]);
    }
    for (i = 1; i < ALLOCS; i++) {
	p[i] = alc_malloc(&alc, i * 4);
    }
    for (i = 1; i < ALLOCS; i++) {
	alc_free(&alc, p[i]);
    }

    gettimeofday(&t2, NULL);

    d1 = TIMEVAL2TS(&t2) - TIMEVAL2TS(&t1);
    printf("memmap: %lu:%lu\n", TS2SEC(d1), TS2USEC(d1));

    memmap_destroy(m);

    gettimeofday(&t1, NULL);
    
    for (i = 1; i < ALLOCS; i++) {
	p[i] = malloc(i * 4);
    }
    for (i = 1; i < ALLOCS; i++) {
	free(p[i]);
    }
    for (i = 1; i < ALLOCS; i++) {
	p[i] = malloc(i * 2);
    }
    for (i = 1; i < ALLOCS; i++) {
	free(p[i]);
    }
    for (i = 1; i < ALLOCS; i++) {
	p[i] = malloc(i * 4);
    }
    for (i = 1; i < ALLOCS; i++) {
	free(p[i]);
    }

    gettimeofday(&t2, NULL);

    d2 = TIMEVAL2TS(&t2) - TIMEVAL2TS(&t1);
    printf("stdlib: %lu:%lu\n", TS2SEC(d2), TS2USEC(d2));
    
    imp = (double) d1 / (double) d2;
    
    if (imp < 1)
	printf("improvement: %%%.0f\n", imp * 100);
    else
	printf("worsening: %%%.0f\n", imp * 100);
    
    return 0;
}

#endif
