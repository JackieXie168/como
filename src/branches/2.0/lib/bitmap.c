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

#include <math.h>    /* log */
#include <strings.h> /* bzero */
#include "bitmap.h"
#include "como.h"
#include "comofunc.h"
#include "memory.h"
#include "comopriv.h"


/*
 * We will be selecting the size of the bitmap depending on the max
 * amount of unique keys the user expects. The following table provides,
 * given the maximum expected number of unique keys, the bitmap size
 * required to count with at most 1% of error.
 *
 * Bitmap sizes must be (in our implementation) a power of 2.
 */
static struct { 
    size_t size;
    size_t max_unique_keys;
} bitmap_sizes[] = {
    { 1<<13,      10869u },
    { 1<<14,      46382u },
    { 1<<15,     134190u },
    { 1<<16,     342020u },
    { 1<<17,     819660u },
    { 1<<18,    1894900u },
    { 1<<19,    4278600u },
    { 1<<20,    9502100u },
    { 1<<21,   20844000u },
    { 1<<22,   45289000u },
    { 1<<23,   97654000u },
    { 1<<24,  209250000u },
    { 1<<25,  446030000u },
    { 1<<26,  946540000u },
    { 1<<27, 2001000000u },
    { 1<<28, 4216000000u },
    { 0, 0 }
};


/*
 * -- new_bitmap, mdl_new_bitmap
 *
 * allocate a bitmap of nbits
 */
static __inline__ void
_initialize_bitmap(bitmap_t *bm, size_t max_keys)
{
    int j; 

    for (j = 0; bitmap_sizes[j].size != 0; j++)
	if (bitmap_sizes[j].max_unique_keys > max_keys)
	    break;

    if (bitmap_sizes[j].size == 0)
	j--;  /* XXX issue a warning to the user? 
               * cannot handle that many keys
	       */

    bm->nbits = bitmap_sizes[j].size;
    bm->bytes = bm->nbits / 8;
    bm->unused_bits = 0;
    if (bm->nbits % 8) {
        bm->bytes++;
        bm->unused_bits = 8 - (bm->nbits % 8);
    }
    bm->zeros = bm->nbits;
}

bitmap_t *
mdl_new_bitmap(void *mdl_self, size_t max_elements)
{
    bitmap_t *bm;

    bm = mdl_malloc(mdl_self, sizeof(bitmap_t));
    _initialize_bitmap(bm, max_elements);
    bm->map = mdl_malloc(mdl_self, bm->bytes);
    bzero(bm->map, bm->bytes);
    return bm;
}

bitmap_t *
new_bitmap(size_t max_elements)
{
    bitmap_t *bm;

    bm = safe_malloc(sizeof(bitmap_t));
    _initialize_bitmap(bm, max_elements);
    bm->map = safe_malloc(bm->bytes); /* no need to bzero */
    return bm;
}

/*
 * -- destroy_bitmap, mdl_destroy_bitmap
 *
 * Free a bitmap.
 */
void
destroy_bitmap(bitmap_t *bm)
{
    free(bm->map);
    free(bm);
}

void
mdl_destroy_bitmap(void *mdl_self, bitmap_t *bm)
{
    mdl_free(mdl_self, bm->map);
    mdl_free(mdl_self, bm);
}

#define which_byte(x) ((x)>>3) /* (x / 8) */
#define which_bit(x)  ((x)&7)  /* (x % 8) */
#define bit_mask(x) (1 << which_bit(x))

/*
 * -- set_bit
 *
 * Set a bit in the bitmap, and maintain the counter of zeros.
 */
void
set_bit(bitmap_t *bm, uint32_t key)
{
    int bit = key & (bm->nbits - 1);
    int where = which_byte(bit);
    int what = which_bit(bit);

#ifndef BUILD_FOR_ARM
    int old;

    /*
     * x86 asm test and set operation
     */
    asm volatile("btsl %2, %1\n\tsbbl %0, %0\n\t"
            : "=r" (old), "=m" (bm->map[where])
            : "r" (what));

    if (old == 0)
        bm->zeros--;
#else
    if (0 == (map[where] & (1 << what))) {
        bm->zeros--;
        map[where] |= 1 << what;
    }
#endif
}

/*
 * -- get_bit
 *
 * Get a bit of the bitmap.
 */
char
get_bit(bitmap_t *bm, int bit)
{
    return (0 != (bm->map[which_byte(bit)] & bit_mask(bit)));
}

/*
 * -- reset_bitmap
 *
 * Clear the contents of a bitmap.
 */
void
reset_bitmap(bitmap_t *bm)
{
    bzero(bm->map, bm->bytes);
    bm->zeros = bm->nbits;
}

/*
 * estimate_unique_keys
 *
 * Return an estimate of the number of unique keys
 * that hit the bitmap. See "A linear-time probabilistic
 * counting algorithm for database applications" by
 * Whang et al for further info.
 */
double
estimate_unique_keys(bitmap_t *bm)
{
    double v;

    if (count_zeros(bm) == 0)
        return 0; /* bitmap full, cannot estimate.. */

    v = ((double)count_zeros(bm)) / (double)bm->nbits;
    return -((double) bm->nbits) * log(v);
}


static int zeros_in_char[256] = {
    8, 7, 7, 6, 7, 6, 6, 5, 7, 6, 6, 5, 6, 5, 5, 4,
    7, 6, 6, 5, 6, 5, 5, 4, 6, 5, 5, 4, 5, 4, 4, 3,
    7, 6, 6, 5, 6, 5, 5, 4, 6, 5, 5, 4, 5, 4, 4, 3,
    6, 5, 5, 4, 5, 4, 4, 3, 5, 4, 4, 3, 4, 3, 3, 2,
    7, 6, 6, 5, 6, 5, 5, 4, 6, 5, 5, 4, 5, 4, 4, 3,
    6, 5, 5, 4, 5, 4, 4, 3, 5, 4, 4, 3, 4, 3, 3, 2,
    6, 5, 5, 4, 5, 4, 4, 3, 5, 4, 4, 3, 4, 3, 3, 2,
    5, 4, 4, 3, 4, 3, 3, 2, 4, 3, 3, 2, 3, 2, 2, 1,
    7, 6, 6, 5, 6, 5, 5, 4, 6, 5, 5, 4, 5, 4, 4, 3,
    6, 5, 5, 4, 5, 4, 4, 3, 5, 4, 4, 3, 4, 3, 3, 2,
    6, 5, 5, 4, 5, 4, 4, 3, 5, 4, 4, 3, 4, 3, 3, 2,
    5, 4, 4, 3, 4, 3, 3, 2, 4, 3, 3, 2, 3, 2, 2, 1,
    6, 5, 5, 4, 5, 4, 4, 3, 5, 4, 4, 3, 4, 3, 3, 2,
    5, 4, 4, 3, 4, 3, 3, 2, 4, 3, 3, 2, 3, 2, 2, 1,
    5, 4, 4, 3, 4, 3, 3, 2, 4, 3, 3, 2, 3, 2, 2, 1,
    4, 3, 3, 2, 3, 2, 2, 1, 3, 2, 2, 1, 2, 1, 1, 0
};


void
or_bitmaps(bitmap_t *dest, bitmap_t *src)
{
    size_t i, size;
    uint32_t zeros;

    size = dest->bytes;
    zeros = -dest->unused_bits;

    for (i = 0; i < size; i++)
        zeros += zeros_in_char[dest->map[i] |= src->map[i]];

    dest->zeros = zeros;
}

#if 0
void 
dump_bitmap(bitmap_t *bm)
{
    size_t i;

    for (i = 0; i < bm->nbits; i++) {
        printf("%d", get_bit(bm, i));
        if (i % 4 == 3)
            printf(" ");
    }
    printf("\n");
}
#endif
