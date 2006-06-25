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

#ifndef BITMAP_H_
#define BITMAP_H_
#include <stdint.h>

struct _bitmap {
    unsigned char *map;     /* bitmap */
    size_t nbits;           /* number of bits in bitmap */
    size_t bytes;           /* number of bytes allocated for bitmap */
    size_t unused_bits;     /* excess allocated bits */
    size_t zeros;           /* number of bits unset */
};
typedef struct _bitmap bitmap_t;

/*
 * -- new_bitmap
 *
 * allocate a bitmap for nbits
 */
bitmap_t * new_bitmap(size_t nbits);
bitmap_t * mdl_new_bitmap(void *mdl_self, size_t nbits);

void destroy_bitmap(bitmap_t *bm);
void mdl_destroy_bitmap(void *mdl_self, bitmap_t *bm);

void reset_bitmap(bitmap_t *bm);

void set_bit(bitmap_t *bm, uint32_t key);
char get_bit(bitmap_t *bm, int bit);

#define count_ones(bm) ((bm)->nbits - (bm)->zeros)
#define count_zeros(bm) ((bm)->zeros)

double estimate_unique_keys(bitmap_t *bm);

#if 0
void dump_bitmap(bitmap_t *bm);
void or_bitmaps(bitmap_t *dest, bitmap_t *src);
#endif

#endif
