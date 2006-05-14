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


#include <stdlib.h>
#include <unistd.h>     /* usleep */
#include <sys/types.h>
#include <sys/mman.h>   /* mmap   */
#include <string.h>     /* bzero  */
#include <assert.h>

#include "como.h"

#define MIN_SIZE	32	/* do not split less than this */

/*
 *

--- ARCHITECTURE ---

The memory allocator manages chunks of memory of variable size,
each described by a 'mem_block_t'. 'size' contains
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

typedef struct _mem_block mem_block_t;

struct _mem_block {
    struct _mem_block *next;
    void *_magic;
#define	MY_MAGIC	(void *)0x91919191
#define	MY_MAGIC_IN_USE	(void *)0x50b50b
    size_t size;			/* actual size of data[] */
    char data[0];
};

/*
 * Entries of a memmap_t.
 */
struct memmap_t {
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
#define MAX_MEMLISTS 	2048
struct _memstate { 
    memmap_t map[MAX_MEMLISTS];    /* the free memory map */
    char * low;			    /* min allowed shared addresses */
    char * high;		    /* max allowed shared addresses */
    int	usage; 			    /* used memory */
    int peak;			    /* peak usage */
}; 
    

extern struct _como map;
struct _memstate * shared_mem; 

static inline int
is_in_shmem(void *x)
{
    return ((char *)x >= shared_mem->low && (char *)x < shared_mem->high);
}

/* 
 * -- checkptr
 * 
 * checks that a block is within the shared memory 
 * region. panics otherwise. 
 * 
 */
static __inline__ void 
checkptr(mem_block_t * x) 
{
    char *c = (char *)x;		

    if (c < shared_mem->low || c >= shared_mem->high)	
	panicx("corrupted ptr %p (instead of %p...%p)\n", 
	       x, shared_mem->low, shared_mem->high);

    if ((x)->_magic != MY_MAGIC && (x)->_magic != MY_MAGIC_IN_USE)
	panicx("bad magic at %p (%p should be %p)\n", 
	       x, (x)->_magic, MY_MAGIC);	
}

#define CHECK_PTR(x)	checkptr((mem_block_t *)(x) - 1)


/*
 * Insert block x into the map m
 */
static void
mem_insert(memmap_t *m, mem_block_t *x)
{
    uint i;

    if (map.mem_type & COMO_SHARED_MEM) 
	checkptr(x); 

    logmsg(V_LOGMEM, "mem_insert %p size %8d, map %p %2d/%8d\n",
	x, x->size, m, first_free(m), map_size(m));

    for (i = 1; i < first_free(m); i++) 
	if (m[i].size == x->size)	/* found the slot */
	    break;
    if (i >= map_size(m)) {		/* We ran out of slots */
	logmsg(LOGWARN, "Warning, must use slot 0 for map %p\n", m);
	x->next = overflow_list(m);
	overflow_list(m) = x;
	return;
    }
    if (i > first_free(m))
	panicx("invalid mem_insert index %d should be %d max %d\n",
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
static int
mem_merge_maps(memmap_t *dst, memmap_t *m)
{
    uint have, need;
    uint i, j;
    uint saved = 0;	/* memory recovered */
    uint orig_src = first_free(m);

    //CHECK_PTR(m); /* FIXME: won't work for heap allocated memmaps. */
    if (dst == NULL)
	dst = shared_mem->map;
    need = first_free(m) - 1;		/* slots we need */
    have = map_size(dst) - first_free(dst);	/* slots we have */

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
	    /* FIXME: HACK!!! */
	    if (x == x->next)
		x->next = NULL;
	    x = x->next;
	    mem_insert(dst, y);
	}
    }
    if (dst == shared_mem->map)
	shared_mem->usage -= saved;
    logmsg(V_LOGMEM, 
	"-- mem_merge_maps %d/%d, %d/%d freed %d in_use %d peak %d\n",
	first_free(dst), map_size(dst), orig_src, map_size(m),
	saved, shared_mem->usage, shared_mem->peak);
    return saved;
}

#define new_mem(m, size)	_new_mem(m, size, __FILE__, __LINE__)

/* 
 * -- _new_mem()
 * 
 * this function allocates a new block of the memory from the 
 * free list. It looks into the lists (memmap_t) to find a block
 * whose is size is equal to the requested size or the smallest 
 * block that would fit the size. In the case the size is not 
 * exactly the same it will split the block and insert the new
 * smaller one in a different list.
 * 
 */
static void *
_new_mem(memmap_t *m, uint size, const char * file, int line)
{
    uint i, cand;
    mem_block_t *x;

    assert(m != NULL);

    logmsg(V_LOGMEM, "new_mem %4d in_use %6d/%6d (map %p %2d/%2d)\n",
	size, shared_mem->usage, shared_mem->peak, m, first_free(m),
        map_size(m));

    cand = 0; 
    i = 1; 
    while (i < first_free(m)) { 
	logmsg(V_LOGMEM, "slot %2d size %8d count %3d p %p\n",
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
	logmsg(LOGWARN, "sorry out of memory for %d bytes (%s:%d)!\n", size,
	       file, line);
	for (i = 1; i < first_free(m); i++)
	    logmsg(V_LOGMEM, "  . slot %2d size %8d count %3d p %p\n",
		i, m[i].size, m[i].count, m[i].next);
	return NULL;
    }

    logmsg(V_LOGMEM, "new_mem need %d have %d at slot %d\n", 
	size, m[cand].size, cand);

    /* we have got a memory block update the memory map */
    x = m[cand].next;
    checkptr(x); 
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
    if (x->size - size > MIN_SIZE + sizeof(mem_block_t)) {
	/* split the block */
	mem_block_t *y = (mem_block_t *)(x->data + size);

	y->size = x->size - size - sizeof(mem_block_t);
	y->_magic = MY_MAGIC;
	x->size = size; /* FIXME: padding? */
	mem_insert(m, y);
    }
    if (m == shared_mem->map) {
	shared_mem->usage += x->size;
	if (shared_mem->usage > shared_mem->peak)
	    shared_mem->peak = shared_mem->usage;
    }
    x->_magic = MY_MAGIC_IN_USE;

    bzero(x->data, x->size); 	/* XXX remove after debugging... */
    return x->data;
}

#define mfree_mem(m, p, size)	_mfree_mem(m, p, size, __FILE__, __LINE__)

/*
 * -- _mfree_mem
 * 
 * Frees the block of memory p into pool m. If a non-zero size is 
 * specified, the size is also checked with the allocation.
 * 
 */
static void
_mfree_mem(memmap_t * m, void * p, uint size, const char * file, int line)	
{
    mem_block_t * x;

    assert(m != NULL);
    if (p == NULL)
	return;

    x = (mem_block_t *)p - 1;
    checkptr(x); 
    if (x->_magic != MY_MAGIC_IN_USE)
	panic("block not in use, %p magic %p (%s:%d)\n", x, x->_magic,
	      file, line);
    x->_magic = MY_MAGIC;
    if (size != 0 && size > x->size)
	panicx("mfree_mem %p size %d real_size %d\n", p, size, x->size);
    logmsg(V_LOGMEM, "mfree_mem %p size %d real_size %d\n", p, size, x->size);
    if (m == shared_mem->map) 
	shared_mem->usage -= x->size;
    mem_insert(m, x);
}


/* 
 * -- memory_init
 * 
 * initialize main memory map. it does an mmap with MAP_ANON
 * to allocate memory and initialize the values in the shared_mem->map. 
 * 
 */
void
memory_init(uint chunk)
{
    mem_block_t *m;

    /*
     * we put the shared memory control structure at the beginning of the
     * chunk, followed by the memory block that contains the actual
     * allocated space.
     */    
    
    shared_mem = mmap((void *)0, chunk*1024*1024, PROT_WRITE|PROT_READ,
	    MAP_ANON|MAP_NOSYNC|MAP_SHARED, -1 /* fd */, (off_t)0);
    if (shared_mem == MAP_FAILED)
	panic("*** failed to allocate %d MB of mapped memory\n", chunk);
    logmsg(LOGMEM, "allocated %d MB of mapped memory\n", chunk);
    
    m = (mem_block_t *)(shared_mem + 1);
    m->size = chunk*1024*1024 - sizeof(struct _memstate) - sizeof(mem_block_t);
    m->_magic = MY_MAGIC;
    m->next = NULL;
    shared_mem->low = shared_mem->high = (char *)m;
    shared_mem->high += chunk*1024*1024 - sizeof(struct _memstate);

    /* create an initial, pseudo-empty map */
    map_size(shared_mem->map) = MAX_MEMLISTS;
    first_free(shared_mem->map) = 1;
    overflow_list(shared_mem->map) = NULL;
    mem_insert(shared_mem->map, m);
}


memmap_t *
memmap_new(allocator_t *alc, uint entries)
{
    memmap_t *x; 

    x = alc_malloc(alc, sizeof(memmap_t)*(1+entries));
    if (x == NULL)
	return NULL;
    map_size(x) = 1+entries;
    first_free(x) = 1;
    overflow_list(x) = NULL;
    return x;
}

void
memmap_destroy(memmap_t *ml)
{
    if (is_in_shmem(ml) == 0)
	return; /* XXX temporary */
	
    mem_merge_maps(shared_mem->map, ml);
    mfree_mem(shared_mem->map, ml, 0);
}

/* 
 * -- mem_copy_map 
 * 
 * this function browse the memmap_t src and re-allocates each 
 * block in that list from the main memory map. it then copies the 
 * content of the src blocks as well. It also find the relative position
 * of the pointer ptr and returns the new relative position (in the copied 
 * memory) of that pointer.  
 *
 */
void * 
mem_copy_map(memmap_t * src, void * ptr, memmap_t * dst) 
{
    void * new_ptr = NULL;
    uint i; 

    for (i = 1; i < first_free(src) ; i++) {
	mem_block_t * x;
	for (x = src[i].next; x != NULL; x = x->next) { 
	    void * p;

	    /* 
	     * allocate a block of the same size, copy this block 
	     * and look for ptr. if the dst memmap is NULL it means 
	     * we don't want to use shared memory. 
	     */
	    if (dst != NULL) { 
		p = new_mem(dst, x->size); 
		if (p == NULL) {
		    /* 
		     * not enough memory in the module region, try
		     * from the main memory region 
		     */
		    p = new_mem(shared_mem->map, x->size); 
		    if (p == NULL) {
			logmsg(LOGWARN, "no mem left to copy master map\n");
			return NULL;	/* XXX handle errors better */
		    }
	  	}
	    } else { 
	        p = safe_malloc(x->size); 
	    } 

	    memcpy(p, x->data, x->size);

	    if ((char *) ptr >= (char *) x->data && 
		(char *) ptr < (char *) x->data + x->size) { 
		new_ptr = ((char *)p + ((char *)ptr - (char *)x->data));
	    } 
	}
    } 

    return new_ptr;
}
	

__inline__ uint 
memory_usage()
{
    return shared_mem->usage;
}

__inline__ uint 
memory_peak()
{
    return shared_mem->peak;
}

void *
_mem_malloc(size_t sz, const char * file, int line)
{
    return _new_mem(shared_mem->map, sz, file, line);
}

void *
_mem_calloc(size_t nmemb, size_t sz, const char * file, int line)
{
    return _new_mem(shared_mem->map, nmemb * sz, file, line);
}

void
_mem_free(void * p, const char * file, int line)
{
    return _mfree_mem(shared_mem->map, p, 0, file, line);
}

__inline__ void 
mem_flush(void * p, memmap_t * m) 
{
    return mfree_mem(m, p, 0);
}

__inline__ int 
mem_free_map(memmap_t * x) 
{
    if (x ==  NULL)
	return 0;
    
    return mem_merge_maps(shared_mem->map, x);
}


/*
 * -- mdl_mem_alloc
 *
 * Allocate memory from a module. if in CAPTURE, allocate in the 
 * module's shared memory space. otherwise do a normal safe_calloc.
 * In persistent mode, all memory regions allocated are always available 
 * to the CAPTURE process. These memory regions represent the starting point 
 * for CAPTURE after it sends all data to EXPORT. 
 * 
 * There are four cases: 
 * 
 *  . private		   --> allocate private memory with safe_calloc;
 *  . shared               --> allocate from shared memory in the mem_map;
 *  . persistent           --> allocate private memory and keep pointers in
 *                             the master_map (useful only for QUERY);
 *  . shared & persistent  --> allocate from shared memory in the master_map
 *                             (useful for SUPERVISOR); 
 * 
 */
void * 
mem_mdl_smalloc(size_t sz, const char * file, int line, module_t * mdl)
{
    mem_block_t *m;
    void *x;
    
    /* check input parameters */
    assert(mdl != NULL);
    assert(sz > 0);
    
    if (map.mem_type & COMO_SHARED_MEM) {
    	/* NOTE: this code doesn't use the mdl->mem_map to get free blocks */
	x = _new_mem(shared_mem->map, sz, file, line);
	if (x == NULL) return NULL;
	
	m = (mem_block_t *) x - 1;
	/* TODO: we don't need a memmap for this, just a list of blocks will
	 * suffice */
	mem_insert(mdl->shared_map, m);
    } else {
	m = safe_calloc(1, sz + sizeof(mem_block_t));
	m->_magic = MY_MAGIC_IN_USE;
	m->size = sz;
	/* TODO: we don't need a memmap for this, just a list of blocks will
	 * suffice */
	mem_insert(mdl->inprocess_map, m);
	x = m->data;
    }
    
    return x; 
}

void *
mem_mdl_scalloc(size_t nmemb, size_t size, const char * file, int line,
		module_t * mdl)
{
    void *ptr;
    
    size *= nmemb;
    ptr = mem_mdl_smalloc(size, file, line, mdl);
    memset(ptr, 0, size);
    return ptr;
}

/*
 * -- mdl_mem_free
 *
 * Free memory from a module. If the pointer is within the shared memory 
 * region, use mfree_mem otherwise use the free() function. 
 */
void
mem_mdl_sfree(void *p, const char * file, int line, module_t * mdl)
{
    /* check input parameters */
    assert(mdl != NULL);

    if ((char *) p < shared_mem->low || (char *) p >= shared_mem->high)
	free(p);
    else 
	_mfree_mem(shared_mem->map, p, 0, file, line);
}

allocator_t *
allocator_safe()
{
    static allocator_t alc = {
	malloc: (alc_malloc_fn) _smalloc,
	calloc: (alc_calloc_fn) _scalloc,
	free: (alc_free_fn) _sfree,
	data: NULL
    };
    
    return &alc;
}

allocator_t *
allocator_shared()
{
    static allocator_t alc = {
	malloc: (alc_malloc_fn) _mem_malloc,
	calloc: (alc_calloc_fn) _mem_calloc,
	free: (alc_free_fn) _mem_free,
	data: NULL
    };
    
    return &alc;
}

void
allocator_init_module(module_t *mdl)
{
    mdl->alc.malloc = (alc_malloc_fn) mem_mdl_smalloc;
    mdl->alc.calloc = (alc_calloc_fn) mem_mdl_scalloc;
    mdl->alc.free = (alc_free_fn) mem_mdl_sfree;
    mdl->alc.data = mdl;
}

