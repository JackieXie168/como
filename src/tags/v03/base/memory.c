/*
 * Copyright (c) 2004, Intel Corporation
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
 * Memory management functions.
 *
 * $Id$
 */

#include <stdlib.h>
#include <unistd.h>     /* usleep */
#include <sys/types.h>
#include <sys/mman.h>   /* mmap   */
#include <string.h>     /* bzero  */

#include "como.h"

#define MIN_SIZE	32	/* do not split less than this */

/*
 *

--- ARCHITECTURE ---

The memory allocator manages chunks of memory of variable size,
each described by a 'mem_block_t'. 'size' contains
the size of the user-portion (data[]) of the block, while
'next' is used to build free lists of blocks, typically of the same size.

Each list is reachable through a 'memlist_t' structure, which
normally contains a pointer to the head of the list, the size
of each entry, and the number of entries in the list.

A memory map is made of an array of such memlist_t's.
Entry #0 is special and used as follows:
  size	is the number of entries in the array;
  count	is the index of the first free entry;
  next	is a pointer to a list of blocks that could not
	fit in the arrays otherwise.
	THE BLOCKS IN THIS LIST MAY HAVE DIFFERENT SIZES.
Entries #1 .. #count-1 contain non-empty lists.
Entries #count .. #size-1 are empty.

The memory allocator functions uses a map as the first parameter.
NULL indicates a special map, private to the process,
which is pointed to by the static variable shared_mem.map.
This map can be reallocated in case it
needs to be extended, and IS NOT in the shared memory segment.

Other maps cannot be reallocated, so when they run out of slots it
is necessary to store elements in entry #0, unsorted.

All allocations are done from maps, and presumably in a shared
memory segment.

Externally visible functions are:

  void * new_mem(memlist_t *map, int size, char *msg)
	returns a block of the desired size from the map;

  void free_mem(memlist_t *map, void *pointer);
	frees the block returning it to the map

  int merge_maps(memlist_t *dst, memlist_t *src);
	merges 'src' into 'dst', invalidating fields in 'src'.
	returns the amount of memory recovered.

  memlist_t *new_memlist(int entries)
	returns a new map (to be freed with free_mem)
 *
 */

typedef struct _mem_block mem_block_t;

struct _mem_block {
    struct _mem_block *next;
    void *_magic;
#define	MY_MAGIC	(void *)0x91919191
#define	MY_MAGIC_IN_USE	(void *)0x50b50b
    uint size;			/* actual size of data[] */
    char data[0];
};

/*
 * Entries of a memlist_t.
 */
struct _memlist {
    mem_block_t *next;
    uint size;			/* user data size */
    uint count;			/* elements in this list */
#define overflow_list(x)	(x)[0].next
#define	map_size(x)		(x)[0].size
#define	first_free(x)		(x)[0].count
};


/*  
 * Memory state
 */
struct _memstate { 
    memlist_t *map;		/* the main map */
    char * low;			/* min allowed shared addresses */
    char * high;		/* max allowed shared addresses */
    int	usage; 			/* used memory */
    int peak;			/* peak usage */
}; 
    

static struct _memstate shared_mem; 


/* 
 * -- checkptr
 * 
 * checks that a block is within the shared memory 
 * region. panics otherwise. 
 * 
 */
__inline__ void 
checkptr(mem_block_t * x) 
{
    char *c = (char *)x;		

    if (c < shared_mem.low || c >= shared_mem.high)	
	panic("corrupted ptr %p (instead of %p...%p)\n", 
		x, shared_mem.low, shared_mem.high);
    if ((x)->_magic != MY_MAGIC && (x)->_magic != MY_MAGIC_IN_USE)
	panic("bad magic at %p (%p should be %p)\n", x, (x)->_magic, MY_MAGIC);	
}

#define CHECK_PTR(x)	checkptr((mem_block_t *)(x) - 1)


/*
 * Insert block x into the map m
 */
static void
mem_insert(memlist_t *m, mem_block_t *x)
{
    uint i, lim;

    if (m == NULL)		/* use the main map */
	m = shared_mem.map;
    checkptr(x); 
    logmsg(V_LOGMEM, "mem_insert %p size %8d, map %p %2d/%8d\n",
	x, x->size, m, first_free(m), map_size(m));
    for (lim = first_free(m), i=1; i<lim; i++)
	if (m[i].size == x->size)	/* found the slot */
	    break;
    if (i >= map_size(m)) {		/* We ran out of slots		*/
	if (m != shared_mem.map) {	/* Cannot realloc, must use slot 0 */
	    logmsg(LOGWARN, "Warning, must use slot 0 for map %p\n", m);
	    x->next = overflow_list(m);
	    overflow_list(m) = x;
	    return;
	} else {			/* Good, can reallocate the map */
	    if (map_size(m) > 128)
		logmsg(LOGWARN, "*** Warning, large map size %d\n", m[0].size);
	    map_size(m) *= 2;	/* Use twice the original size */
	    m = safe_realloc(m, map_size(m)*sizeof(*m));
	    logmsg(LOGMEM, "mem_insert: realloc map with size %d\n",
		    map_size(m));
	    shared_mem.map = m;
	}
    }
    if (i > first_free(m))
	panic("*** invalid mem_insert index %d should be %d max %d\n",
		i, first_free(m), map_size(m));
    if (i == first_free(m)) {		/* Previously empty slot */
	first_free(m)++;
	m[i].next = NULL;
	m[i].size = x->size;
	m[i].count = 0;
    }
    x->next =m[i].next;
    m[i].count++;
    m[i].next = x;
}

/*
 * merge map m into dst.
 * We expect the number of slots to be small, so rather than use
 * a complex sorting/merging algorithm, just concatenate the maps
 * unless there is major trouble which requires individual entries
 * to be merged in.
 * It returns the amount of memory recovered thru merging. 
 */
int
mem_merge_maps(memlist_t *dst, memlist_t *m)
{
    uint have, need;
    uint i, j;
    uint saved = 0;	/* memory recovered */
    uint orig_src = first_free(m);

    CHECK_PTR(m); 
    if (dst == NULL)
	dst = shared_mem.map;
    need = first_free(m) - 1;		/* slots we need */
    have = map_size(dst) - first_free(dst);	/* slots we have */
    if (have < need && dst == shared_mem.map) {	/* can reallocate, do it */
	map_size(dst) += need - have;
	dst = safe_realloc(dst, map_size(dst)*sizeof(memlist_t));
	logmsg(V_LOGMEM, "---- mem_merge_maps: realloc map with size %d\n",
		map_size(dst));
	shared_mem.map = dst;
	have = need;
    }

#if 0 	/* XXX debugging info */
    for (i=1; i < first_free(dst); i++)
	logmsg(V_LOGMEM, "-- dst[%2d] size %3d count %d\n",
		i, dst[i].size, dst[i].count);
    for (i=1; i < first_free(m); i++)
	logmsg(V_LOGMEM, "-- src[%2d] size %3d count %d\n",
		i, m[i].size, m[i].count);
#endif

    if (need <= have) {			/* easy... */
	for (i=1, j=first_free(dst); i < first_free(m) ; i++, j++) {
	    dst[j] = m[i];
	    saved += dst[j].size * dst[j].count;
	}
	first_free(dst) = j;
	first_free(m) = 1;
    }
    j = first_free(m);			/* leftover lists */
    if (j > 1 || overflow_list(m) != NULL)
	logmsg(LOGWARN, "*** WARNING, full map (j %d, next %p)\n",
		j, overflow_list(m));

    /* copy individual elements from leftover lists if any */
    for (i=0; i < j; i++) {
	mem_block_t *x, *y;
	for (x = m[i].next; x; ) {
	    saved += x->size;
	    y = x;
	    x = x->next;
	    mem_insert(dst, y);
	}
    }
    if (dst == shared_mem.map)
	shared_mem.usage -= saved;
    logmsg(V_LOGMEM, 
	"-- mem_merge_maps %d/%d, %d/%d freed %d in_use %d peak %d\n",
	first_free(dst), map_size(dst), orig_src, map_size(m),
	saved, shared_mem.usage, shared_mem.peak);
    return saved;
}

void *
new_mem(memlist_t *m, uint size, __unused char *msg)
{
    uint i, cand;
    mem_block_t *x;

    if (m == NULL)
	m = shared_mem.map;
    else
	panic("alloc from unsupported map XXX fixme\n");
    if (m == NULL)
	panic("memory not initialized\n");

    logmsg(V_LOGMEM, "-- new_mem %4d in_use %6d/%6d (map %p %2d/%2d)\n",
	size, shared_mem.usage, shared_mem.peak, m, first_free(m), map_size(m));
    for (cand = 0, i=1; i<first_free(m);) {
	logmsg(V_LOGMEM, "   slot %2d size %8d count %3d p %p\n",
		i, m[i].size, m[i].count, m[i].next);
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
	logmsg(V_LOGMEM, "sorry out of memory for %d bytes (%s)!\n", size, msg);
	for (i=1; i < first_free(m);i++)
	    logmsg(V_LOGMEM, "   slot %2d size %8d count %3d p %p\n",
		i, m[i].size, m[i].count, m[i].next);
	return NULL;
    }
    logmsg(V_LOGMEM, "-- new_mem need %d have %d at slot %d\n", 
	size, m[cand].size, cand);
    x = m[cand].next;
    checkptr(x); 
    m[cand].count--;
    m[cand].next = x->next;
    x->next = NULL;
    if (m[cand].next == NULL) {	/* slot now empty, replace with last one */
	first_free(m)--;
	m[cand] = m[first_free(m)];
    } else if (cand != 1) {	/* move to front. */
	memlist_t y = m[cand];
	m[cand] = m[1];
	m[1] = y;
    }
    if (x->size - size > MIN_SIZE + sizeof(mem_block_t)) {
	/* split the block */
	mem_block_t *y = (mem_block_t *)(x->data + size);

	y->size = x->size - size - sizeof(mem_block_t);
	y->_magic = MY_MAGIC;
	x->size = size;
	mem_insert(m, y);
    }
    if (m == shared_mem.map) {
	shared_mem.usage += x->size;
	if (shared_mem.usage > shared_mem.peak)
	    shared_mem.peak = shared_mem.usage;
    }
    x->_magic = MY_MAGIC_IN_USE;
    bzero(x->data, size);	/* XXX check this. */
    return x->data;
}

/*
 * Frees the block of memory p into pool m.
 * If a non-zero size is specified, the size is also checked with the
 * allocation, and the block is zeroed to detect stale pointers etc
 * (XXX the zeroing will go away once the code is debugged).
 */
void
mfree_mem(memlist_t *m, void *p, uint size)	/* equivalent to free(p) */
{
    mem_block_t *x = (mem_block_t *)p - 1;

    if (m == NULL) 	/* if m is NULL use default map */
	m = shared_mem.map; 

    checkptr(x); 
    if (x->_magic != MY_MAGIC_IN_USE)
	panic("block not in use, %p magic %p\n", x, x->_magic);
    x->_magic = MY_MAGIC;
    if (size != 0) {
	if (size > x->size)
	    panic("mfree_mem %p size %d real_size %d\n", p, size, x->size);
	bzero(p, size);
    }
    logmsg(V_LOGMEM, "mfree_mem %p size %d real_size %d\n", p, size, x->size);
    if (m == shared_mem.map) 
	shared_mem.usage -= x->size;
    mem_insert(m, x);
}


/*
 * -- memory_clear
 *
 * Used by clients to reset mapping 
 *
 */
void 
memory_clear() 
{
    logmsg(LOGMEM, "freeing memory map\n");
    free(shared_mem.map);
    shared_mem.map = 0;
    return;
}

void
memory_init(uint chunk)
{
    static int done;
    mem_block_t *m;

    if (done)
	panic("*** can only do memory_init() once\n");
    done = 1;
    m = mmap((void *)0, chunk*1024*1024, PROT_WRITE|PROT_READ,
	    MAP_ANON|MAP_NOSYNC|MAP_SHARED, -1 /* fd */, (off_t)0);
    if (m == MAP_FAILED)
	panic("*** failed to allocate %d MB of mapped memory\n", chunk);
    logmsg(LOGMEM, "allocated %d MB of mapped memory\n", chunk);
    shared_mem.low = shared_mem.high = (char *)m;
    shared_mem.high += chunk*1024*1024;

    m->size = chunk*1024*1024 - sizeof(mem_block_t);
    m->_magic = MY_MAGIC;
    m->next = NULL;

    /* allocate an initial, pseudo-empty map */
    shared_mem.map = calloc(1, sizeof(memlist_t));
    map_size(shared_mem.map) = 1;
    first_free(shared_mem.map) = 1;
    overflow_list(shared_mem.map) = NULL;
    mem_insert(NULL, m);
}

__inline__ uint 
memory_usage()
{
    return shared_mem.usage;
}

__inline__ uint 
memory_peak()
{
    return shared_mem.peak;
}

memlist_t *
new_memlist(uint entries)
{
    memlist_t *x; 

    x = new_mem(NULL, sizeof(memlist_t)*(1+entries), "new_memlist_t" );
    map_size(x) = 1+entries;
    first_free(x) = 1;
    overflow_list(x) = NULL;
    return x;
}
