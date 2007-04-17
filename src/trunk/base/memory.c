/*
 * Copyright (c) 2004-2007, Intel Corporation
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
#include <sys/types.h>
#include <sys/mman.h>   /* mmap   */
#include <string.h>     /* bzero  */
#include <assert.h>

#include "como.h"

/*
 *

--- ARCHITECTURE ---

The memory allocator manages chunks of memory of variable size,
each described by a 'mem_block_t'. 'size' contains
the size of the user-portion (data[]) of the block, while
'next' is used to build free lists of blocks always of the same size.
The size is restricted to be a power of 2 between 2^MIN_BLOCK_SIZE
and 2^(MAX_BLOCK_SIZE + MIN_BLOCK_SIZE). 

The lists are reachable through a 'memmap_t' structure, which
normally contains a pointer to the head of the list, the size
of each entry, and the number of entries in the list.

A memory map is made of an array of such the head pointers and 
bitmap that tells which head pointers are not NULL. 

The memory state is stored at the very beginning of the shared 
memory and contains a global memmap, two pointers to indicate the
beginning and end of the shared memory and current usage and peak 
usage stats. 

 *
 */

#define MIN_BLOCK_SIZE		5	/* 2^5 = 32 bytes */ 
#define MAX_BLOCK_SIZE 		25 	/* 2^(25+5) = 1 GBytes */ 

#define BITSET(x)		(1<<x)
#define BITMASK(x)		(~BITSET(x)) 

typedef struct _mem_block mem_block_t;

struct _mem_block {
    struct _mem_block *next;
    void *_magic;
#define	MY_MAGIC	(void *)0x91919191
#define	MY_MAGIC_IN_USE	(void *)0x50b50b
    size_t request; 			/* requested size of mem block */
    size_t size;			/* actual size of data[] */
    char data[0];
};


/*
 * memory map. 
 * it consists of MAX_BLOCK_SIZE single linked lists
 * that contain each memory block. plus the used_bitmap
 * that tells which lists do have elements, i.e. bit i in 
 * used_bitmap is set if blocks[i] is not NULL. 
 */
struct _memmap {
    mem_block_t * blocks[MAX_BLOCK_SIZE];
    uint used_bitmap; 		
}; 


/*  
 * Memory state
 */
struct _memstate { 
    memmap_t map;		/* the free memory map */
    char * low;			/* min allowed shared addresses */
    char * high;		/* max allowed shared addresses */
    uint usage;			/* used memory */
    uint waste; 		/* wasted memory due to power2 allocator */ 
    uint peak;			/* peak usage */
}; 
    

extern struct _como map;
struct _memstate * shared_mem; 

/* 
 * -- is_in_shMem
 * 
 * true if x points somewhere in our shared memory.
 *
 */ 
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
static inline void 
checkptr(mem_block_t * x) 
{
    if (!is_in_shmem(x)) 
	panicx("corrupted ptr %p (instead of %p...%p)\n", 
	       x, shared_mem->low, shared_mem->high);

    if ((x)->_magic != MY_MAGIC && (x)->_magic != MY_MAGIC_IN_USE)
	panicx("bad magic at %p (%p should be %p)\n", 
	       x, (x)->_magic, MY_MAGIC);	
}
#define CHECK_PTR(x)	checkptr((mem_block_t *)(x) - 1)


/*
 * -- fit_power2
 * 
 * find the smallest power of 2 that is 
 * larger than (or equal to) x. 
 * we use a simple binary search for the largest bit set in 
 * x and then account for exact match.
 */ 
static uint
fit_power2(uint x)
{
    uint w_hi = sizeof(x) * 8; 
    uint w_lo = 1; 

    while (w_hi - w_lo > 1) { 
	uint w = (w_hi - w_lo) / 2 + w_lo; 
	uint v = 1 << w; 

	if (x < v)
	    w_hi = w; 
 	else if (x > v) 
	    w_lo = w; 
	else 
	    return w; 
    } 

    return w_hi; 
}


/*
 * -- mem_insert 
 * 
 * Insert block x into the map m. This happens when 
 * allocating for maps that keep track of allocated 
 * blocks or when freeing for the master map. 
 * 
 */
static void
mem_insert(memmap_t *m, mem_block_t *x)
{
    uint w; 

    if (map.mem_type & COMO_SHARED_MEM) 
	checkptr(x); 

    assert(x->size >= (1 << MIN_BLOCK_SIZE)); 

    w = fit_power2(x->size); 

    w -= MIN_BLOCK_SIZE; 
    if (w > MAX_BLOCK_SIZE) {
	logmsg(LOGWARN, "cannot process blocks of size %d > 2^%d bytes\n", 
	       x->size, MAX_BLOCK_SIZE + MIN_BLOCK_SIZE); 
	return; 
    } 

    if (m->blocks[w] == NULL) 
	m->used_bitmap |= (1 << w); 
    x->next = m->blocks[w];
    m->blocks[w] = x; 

    /* XXX at this point we could defrag the memory coalescing 
     *     adjacent blocks. for now, we go without aggregating 
     *     small blocks. 
     */
}


/*
 * -- mem_merge_maps 
 * 
 * merge map m into dst. we insert each block of m into the 
 * related list in dst making sure that all list are always 
 * of the same size. given that blocks are power of 2, there 
 * shouldn't be that many different sizes in m. . 
 * 
 * It returns the amount of memory recovered thru merging. 
 * 
 */
static int
mem_merge_maps(memmap_t *dst, memmap_t *m)
{
    uint w; 
    uint saved = 0;		/* memory recovered */
    uint waste_saved = 0; 	/* update wastage count */ 


    /* browse the free_bitmap, if there is a bit set merge the 
     * related list with the one in the same location for dst 
     */ 
    for (w = 0; w < sizeof(m->used_bitmap)*8; w++) { 
	if (m->used_bitmap & BITSET(w)) { 
	    mem_block_t *p, *q; 
		
	    /* get to the tail of the list in m */
	    q = p = m->blocks[w]; 
	    while (p) {
		saved += p->size;
		waste_saved += p->size - p->request; 
		p->_magic = MY_MAGIC; 	/* blocks are freed */
		q = p; 
		p = p->next; 
	    } 

	    /* include last block */ 
		
	    /* merge the lists */
	    if (dst->blocks[w] == NULL) 
		dst->used_bitmap |= BITSET(w); 
	    q->next = dst->blocks[w]; 
	    dst->blocks[w] = m->blocks[w]; 
	} 
    } 

    if (dst == &shared_mem->map) { 
	shared_mem->usage -= saved;
	shared_mem->waste -= waste_saved;
	logmsg(V_LOGMEM, "returned %d bytes to main map\n", saved); 
    } 

    return saved; 
}


#define new_mem(m, size)	_new_mem(m, size, __FILE__, __LINE__)

/* 
 * -- _new_mem()
 * 
 * this function allocates a new block of the memory from the 
 * free list. It looks into the lists (memmap_t) to find a block
 * whose is size is equal to the requested size or the smallest 
 * block that would fit the size. the allocated block will always 
 * be of a size that is a power of 2. 
 * 
 */
static void *
_new_mem(memmap_t *m, uint size, const char * file, int line)
{
    int w, cand; 
    mem_block_t *x;

    assert(m != NULL);

    if (size > 1 << (MAX_BLOCK_SIZE + MIN_BLOCK_SIZE)) {
	logmsg(LOGWARN, "cannot allocate blocks of %d > %d bytes (%s:%d)\n", 
	       size, 1 << (MAX_BLOCK_SIZE + MIN_BLOCK_SIZE), file, line); 
	return NULL; 
    } 

    /* find the smallest power of 2 >= size */ 
    w = fit_power2(size + sizeof(mem_block_t)); 
    w -= MIN_BLOCK_SIZE; 
    if (w < 0) 
	w = 0;

    /* find the smallest available block size that is >= size */
    for (cand = w; cand < MAX_BLOCK_SIZE; cand++) 
	if (m->used_bitmap & BITSET(cand)) 
	    break; 

    if (cand == MAX_BLOCK_SIZE) {
	logmsg(LOGWARN, "sorry out of memory for %d bytes (%s:%d)!\n", size,
	       file, line);
	return NULL;
    }

    logmsg(LOGMEM, "new_mem need %d have %d\n", size, 1 << cand); 

    /* we have got a memory block. remove it from the map. 
     * then check if we can split it in smaller blocks before allocating it. 
     */ 
    x = m->blocks[cand]; 
    x->request = size; 
    m->blocks[cand] = x->next; 
    if (m->blocks[cand] == NULL) 
	m->used_bitmap &= BITMASK(cand); 

    while (cand > w) { 
	mem_block_t * p;
	size_t sz; 

	/* split the block in two. one is put back in the 
	 * map while we keep the other one (that can be 
	 * split further)
	 */
	sz = x->size / 2; 
	p = (mem_block_t *)((char *)x + sz); 
	p->size = sz; 
	p->_magic = MY_MAGIC; 

	/* link it to the previous entry in the map */
	cand--;
	p->next = m->blocks[cand]; 
	m->blocks[cand] = p; 
	m->used_bitmap |= BITSET(cand);
	
	x->size = sz; 
    } 
	
    if (m == &shared_mem->map) {
	shared_mem->usage += x->size; 
	shared_mem->waste += x->size - size;
	if (shared_mem->usage > shared_mem->peak)
	    shared_mem->peak = shared_mem->usage;
    }

    x->request = size; 
    x->_magic = MY_MAGIC_IN_USE;
    bzero(x->data, x->size - sizeof(mem_block_t)); /* XXX for debugging only */
    return x->data;
}

#define mfree_mem(m, p)	_mfree_mem(m, p, __FILE__, __LINE__)

/*
 * -- _mfree_mem
 * 
 * Frees the block of memory p into pool m. If a non-zero size is 
 * specified, the size is also checked with the allocation.
 * 
 */
static void
_mfree_mem(memmap_t * m, void * p, const char * file, int line)	
{
    mem_block_t * x;

    assert(m != NULL);
    if (p == NULL)
	return;

    x = (mem_block_t *)p - 1;
    checkptr(x); 
    if (x->_magic != MY_MAGIC_IN_USE)
	panic("wrong magic at %p:%p (%s:%d)\n", x, x->_magic, file, line);
    x->_magic = MY_MAGIC;
    if (m == &shared_mem->map) {
	shared_mem->usage -= x->size;
	shared_mem->waste -= x->size - x->request; 
    } 
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
    uint real, left, used_mem; 

    real = 1 << fit_power2(chunk);	/* actual memory size */  
    if (real != chunk) 
	logmsg(LOGWARN, "memsize %dMB not a power of 2. rounding to %dMB\n", 
	       chunk, real); 

    real <<= 20; 			/* convert to MBytes */

    /*
     * we put the shared memory control structure at the beginning of the
     * chunk, followed by the memory block that contains the actual
     * allocated space.
     */    
    
    shared_mem = mmap((void *)0, real, PROT_WRITE|PROT_READ,
	    MAP_ANON|MAP_NOSYNC|MAP_SHARED, -1 /* fd */, (off_t)0);
    if (shared_mem == MAP_FAILED)
	panic("*** failed to allocate %d MB of mapped memory\n", chunk);
    logmsg(LOGMEM, "allocated %d MB of mapped memory\n", chunk);
    
    /* 
     * we now need to populate the main map. note that a bit of memory
     * is used to contain the main map itself, exactly sizeof(_memstate). 
     * we will consume a bit more than that to make it a power of 2. 
     */
    used_mem = 1 << fit_power2(sizeof(struct _memstate)); 
    if (used_mem < 1 << MIN_BLOCK_SIZE)
	used_mem = 1 << MIN_BLOCK_SIZE; 
    shared_mem->low = (char *)shared_mem + used_mem;
    shared_mem->high = (char *)shared_mem + real;

    left = real - used_mem; 
    while (left > 0) { 
	m = (mem_block_t *)((char *)shared_mem + used_mem); 
        m->size = used_mem; 
        m->_magic = MY_MAGIC; 
        m->next = NULL; 
	mem_insert(&shared_mem->map, m); 
 	left -= used_mem; 
	used_mem <<= 1; 
    } 

    assert(left == 0); 
    assert(used_mem == real); 
}


memmap_t *
memmap_new(allocator_t *alc)
{
    memmap_t *x; 

    x = alc_malloc(alc, sizeof(memmap_t));
    if (x == NULL)
	return NULL;
    bzero(x, sizeof(memmap_t)); 
    return x;
}

void
memmap_destroy(memmap_t *ml)
{
    mem_merge_maps(&shared_mem->map, ml);
    mfree_mem(&shared_mem->map, ml);
}


uint 
memory_usage()
{
    return shared_mem->usage;
}

uint 
memory_waste()
{
    return shared_mem->waste;
}

uint 
memory_peak()
{
    return shared_mem->peak;
}

void *
_mem_malloc(size_t sz, const char * file, int line)
{
    return _new_mem(&shared_mem->map, sz, file, line);
}

void *
_mem_calloc(size_t nmemb, size_t sz, const char * file, int line)
{
    return _new_mem(&shared_mem->map, nmemb * sz, file, line);
}

void
_mem_free(void * p, const char * file, int line)
{
    return _mfree_mem(&shared_mem->map, p, file, line);
}

void 
mem_flush(void * p, memmap_t * m) 
{
    return mfree_mem(m, p);
}

int 
mem_free_map(memmap_t * x) 
{
    if (x ==  NULL)
	return 0;
    
    return mem_merge_maps(&shared_mem->map, x);
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
	x = _new_mem(&shared_mem->map, sz, file, line);
	if (x == NULL) 
	    return NULL;
	
	m = (mem_block_t *) x - 1;
	/* TODO: we don't need a memmap for this, just a list of blocks will
	 * suffice */
	mem_insert(mdl->shared_map, m);
    } else {
	m = safe_calloc(1, sz + sizeof(mem_block_t));
	m->_magic = MY_MAGIC_IN_USE;
	m->size = sz;
	/* XXX we don't use the inprocess_map yet. the plan is to use 
 	 *     it only for bookkeeping anyway. 
	 */
#if 0 
	mem_insert(mdl->inprocess_map, m);
#endif
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
 * -- mem_mdl_sfree
 *
 * Free memory from a module. If the pointer is within the shared memory 
 * region, use mfree_mem otherwise use the free() function. 
 */
void
mem_mdl_sfree(void *p, const char * file, int line, module_t * mdl)
{
    /* check input parameters */
    assert(mdl != NULL);

    if ((char *) p < shared_mem->low || (char *) p >= shared_mem->high) {
	/* this block is in system memory. move back by one mem_block_t 
         * and free that pointer. 
         */ 
	char * m = ((char *) p) - sizeof(mem_block_t); 
	free(m);
    } else {
	_mfree_mem(&shared_mem->map, p, file, line);
    } 
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

