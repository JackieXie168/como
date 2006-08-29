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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include "como.h"

/* 
 * -- rdtsc()
 * 
 * read the timestamp counter (TSC) and return its value (64 bit)
 * 
 */
static __inline__ uint64_t
rdtsc(void)
{
    u_int64_t rv;
#ifdef BUILD_FOR_ARM 
    rv = 0; 
#else
    __asm __volatile(".byte 0x0f, 0x31" : "=A" (rv));
#endif
    return (rv);
}


/* 
 * -- new_tsctimer()
 * 
 * allocate a new tsc_t data structure and initilize it
 */
tsc_t *
new_tsctimer(char * name)
{
    tsc_t * t; 

    t = safe_calloc(1, sizeof(tsc_t)); 
    t->name = safe_strdup(name); 
    t->min = ~0; 
    return t;
}


/* 
 * -- destroy_tsctimer()
 * 
 * free the tsc_t data structure;
 */
void 
destroy_tsctimer(tsc_t * t)
{
    safe_free(t->name); 
    safe_free(t); 
}


/* 
 * -- reset_tsctimer()
 * 
 * resets an existing tsc_t data structure 
 */
void 
reset_tsctimer(tsc_t * t)
{
    assert(t != NULL); 
    t->n = 0; 
    t->total = 0;
    t->max = 0; 
    t->min = ~0; 
}


/* 
 * -- start_tsctimer
 * 
 * gather first TSC reading. 
 * this is going to be the reference for future readings. 
 */
__inline__ void
start_tsctimer(tsc_t *t)
{
    t->value = rdtsc(); 
}


/* 
 * -- end_tsctimer
 * 
 * gather another TSC reading and compute the difference with 
 * previous reading. also update min, max and total.  
 */
__inline__ void
end_tsctimer(tsc_t *t)
{
    uint64_t x = rdtsc();

    t->value = x - t->value; 
    if (t->value < t->min)
	t->min = t->value;
    if (t->value > t->max)
	t->max = t->value;
    t->total += t->value;
    t->n++;
}


/* 
 * -- get_avg_sample
 * 
 * return the average over all samples. 
 */
__inline__ uint64_t
get_avg_sample(tsc_t *t)
{ 
    return ((t->n)? (t->total / t->n) : 0); 
}


/* 
 * -- get_min_sample
 * 
 * return the minimum over all samples. 
 */
__inline__ uint64_t
get_min_sample(tsc_t *t)
{ 
    return ((t->n)? t->min : 0); 
}


/* 
 * -- get_max_sample
 * 
 * return the maximum over all samples. 
 */
__inline__ uint64_t
get_max_sample(tsc_t *t)
{ 
    return ((t->n)? t->max : 0); 
}


/* 
 * -- print_tsctimer 
 *
 * returns a string for pretty-printing the samples
 */
char * 
print_tsctimer(tsc_t *t) 
{ 
    static char str[1024]; 

    sprintf(str, "%s n %d min %llu avg %llu max %llu", 
	t->name, t->n, get_min_sample(t), get_avg_sample(t), get_max_sample(t)); 

    return str; 
}

