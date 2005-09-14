/*
 * Copyright (c) 2005 Universitat Politecnica de Catalunya
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

/*
 * Author: Diego Amores Lopez (damores@ac.upc.edu)
 * 
 * Description:
 * ------------
 *  
 * Snort module for CoMo - private memory management
 * 
 * The functions in this file allow the Snort module for CoMo to use dynamic
 * memory allocation inside the private memory region designated for it.
 * 
 * This has been implemented in order to use external libraries (libpcre)
 * or software (Flex, Bison), so that they can call these functions instead
 * of the standard malloc, realloc and free. But these functions are also
 * useful to ease memory management in the module itself.
 *
 * Most of the code has been adapted from chapter 8.7 of the book
 * "The C Programming Language" by Brian Kernighan and Dennis Ritchie.
 * 
 */

#include <stdlib.h>     /* NULL, size_t */
#include <stdint.h>     /* uint8_t, etc. */
#include <string.h>     /* memcpy */
#include <stdio.h>      /* snprintf */
#include "snort.h"      /* yserror */

#define MIN(a,b) (a < b) ? a : b

typedef long align_t;

union header {
    struct {
        union header *ptr;
        unsigned int size;
    } s;
    align_t x;
};

typedef union header header_t;

static header_t *freep = NULL; /* start of free list */
static header_t membase; /* empty list to get started */

/* Needed to manage the module's private memory region
 * These variables are defined in modules/newsnort.c 
 */
extern void *prv_mem;
extern size_t prv_actualsize;
extern size_t prv_memsize;

/* 
 * -- prv_free
 *
 * Put block ap in free list
 *
 */

void prv_free(void *ap)
{
    header_t *bp, *p;
    bp = (header_t *)ap - 1; /* point to block header */
    for (p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
        if (p >= p->s.ptr && (bp > p || bp < p->s.ptr))
            break; /* freed block at start or end of arena */
    if (bp + bp->s.size == p->s.ptr) { /* join to upper nbr */
        bp->s.size += p->s.ptr->s.size;
        bp->s.ptr = p->s.ptr->s.ptr;
    } else
        bp->s.ptr = p->s.ptr;
    if (p + p->s.size == bp) { /* join to lower nbr */
            p->s.size += bp->s.size;
            p->s.ptr = bp->s.ptr;
    } else
        p->s.ptr = bp;
    freep = p;
}

static header_t *morecore(unsigned nunits)
{
    header_t *up;
    size_t nbytes;
    char error[ERROR_SIZE];
    
    nbytes = nunits * sizeof(header_t);
    prv_actualsize += nbytes;
    if (prv_actualsize > prv_memsize) {
        snprintf(error, ERROR_SIZE, "Not enough private memory %d/%d",
                 prv_actualsize, prv_memsize);
        yserror(error);
        return NULL;
    }
    prv_mem += nbytes;
    up = (header_t *)(prv_mem - nbytes);
    up->s.size = nunits;
    prv_free((void *)(up + 1));
    return freep;
}

/*
 * -- prv_alloc
 *
 * Allocate nbytes of memory in the private memory
 * space of the module
 *
 */

void *
prv_alloc(unsigned int nbytes)
{
    header_t *p, *prevp;
    unsigned int nunits;
    
    nunits = (nbytes + sizeof(header_t) - 1) / sizeof(header_t) + 1;
    if ((prevp = freep) == NULL) { /* no free list yet */
        membase.s.ptr = freep = prevp = &membase;
        membase.s.size = 0;
    }
    for (p = prevp->s.ptr; ; prevp = p, p = p->s.ptr) {
        if (p->s.size >= nunits) { /* big enough */
            if (p->s.size == nunits) /* exact size */
                prevp->s.ptr = p->s.ptr;
            else {
                p->s.size -= nunits;
                p += p->s.size;
                p->s.size = nunits;
            }
            freep = prevp;
            return (void *)(p + 1);
        }
        if (p == freep) /* wrapped around free list */
            if ((p = morecore(nunits)) == NULL)
                return NULL;
    }
}

/*
 * -- prv_realloc
 *
 */

void *
prv_realloc(void *ptr, unsigned int nbytes)
{
    header_t *bp;
    void *p;
    unsigned int size;
    
    bp = (header_t *)ptr - 1;
    size = MIN(((bp->s.size - 1) * sizeof(header_t)), nbytes); 
    p = prv_alloc(nbytes);
    memcpy(p, ptr, size);
    prv_free(ptr);
    return p; 
}
