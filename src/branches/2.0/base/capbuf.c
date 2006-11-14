/* 
 * Copyright (c) 2006, Intel Corporation 
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

#include <sys/mman.h>
#include <assert.h>

/* a simple ring buffer to be used by sniffers to capture packets */
typedef struct capbuf {
    void *	base;
    void *	end;
    void *	tail;
    size_t	size;
    size_t	ofcheck;
} capbuf_t;

/*
 * -- capbuf_init
 * 
 * Initializes a capbuf. The buffer memory is allocalted as an anonymous
 * shared memory map.
 * 
 */
static int
capbuf_init(struct capbuf * capbuf, const char * args, const char * arg,
	    size_t min_size, size_t max_size)
{
    size_t sz = min_size;
    if (arg == NULL) {
	arg = "capbuf=";
    }

    if (args) {
	char *p;
	if ((p = strstr(args, arg)) != NULL) {
	    sz = atoi(p + 7);
	    sz = ROUND_32(sz);
	    if (sz < min_size) {
	    	sz = min_size;
	    }
	    if (sz > max_size) {
		sz = max_size;
	    }
	}
    }

    /* create the capture buffer */
    capbuf->base = mmap((void *) 0, sz, PROT_WRITE | PROT_READ,
			MAP_ANON | MAP_NOSYNC | MAP_SHARED, -1 /* fd */, 0);
    if (capbuf->base == MAP_FAILED)
	return -1;
    
    capbuf->size = sz;
    capbuf->end = capbuf->base + sz;
    capbuf->tail = capbuf->base;
    
    return 0;
}


/*
 * -- capbuf_finish
 * 
 * Finalizes a capbuf.
 * 
 */
static int
capbuf_finish(struct capbuf * capbuf)
{
    int ret = 0;
    if (capbuf->base) {
	ret = munmap(capbuf->base, capbuf->size);
	capbuf->base = NULL;
    }
    return ret;
}


static inline size_t
capbuf_region_size(struct capbuf * capbuf, void * x, void * y)
{
    if (y >= x) {
	return y - x;
    }
    return capbuf->size - (x - y);
}


static void
capbuf_begin(struct capbuf * capbuf, void * head)
{
    if (head == NULL) {
	capbuf->ofcheck = 0;
    } else {
	capbuf->ofcheck = capbuf_region_size(capbuf, head, capbuf->tail);
    }
}


/*
 * -- capbuf_reserve_space
 * 
 * Reserves a contigous memory area of size s bytes from the capbuf and
 * returns the base pointer.
 * 
 */
static inline void *
capbuf_reserve_space(struct capbuf * capbuf, size_t s)
{
    void *end;
    
    //s = ROUND_32(s);
    assert(s > 0);
    capbuf->ofcheck += s;
    if (capbuf->ofcheck > capbuf->size)
	error("capbuf overflow");
    
    end = capbuf->tail + s;
    if (end > capbuf->end) {
	end = capbuf->base + s;
    }
    capbuf->tail = end;

    return capbuf->tail - s;
}


/*
 * -- capbuf_truncate
 *
 * Truncates the space that was reserved with capbuf_reserve_space.
 * 
 */
static inline void
capbuf_truncate(struct capbuf * capbuf, void * x)
{
    //x = (void *) ROUND_32((uint32_t) x);
    assert(x <= capbuf->tail);
    capbuf->ofcheck -= capbuf->tail - x;
    capbuf->tail = x;
}
