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

#include <stdlib.h>     /* rand */
#include <assert.h>
#include "uhash.h"

/*
 * -- uhash_initialize
 *
 * Given a uhash_t, initialize it and randomly choose the actual
 * hash function.
 */
void
uhash_initialize(uhash_t *h)
{
    uint32_t *m = h->m;
    int i;

    for (i = 0; i < H3_BASE * H3_KEYLEN; i++)
        *(m++) = (rand() << 16) | (rand() & 0xffff);

    h->position = -1;
    h->value = 0;
}


/*
 * -- uhash
 *
 * Hash the given data. Always call uhash_restart before uhash.
 * Can be called several times to compute the hash key of a
 * non-contiguous memory region (do not call uhash_restart
 * between the calls to uhash). The hash value is the last return
 * value. Do never hash more than H3_KEYLEN bytes.
 */
uint32_t
uhash(uhash_t *h, uint8_t *key, size_t length, int type) 
{
    size_t i;

    if (type == UHASH_NEW) {
	h->position = -1;
	h->value = 0;
    } 

    for (i = 0; i < length; i++) {
        h->position += key[i] + 1;
        assert(h->position < H3_BASE * H3_KEYLEN); /* check bounds */
        h->value ^= h->m[h->position];
    }
    return h->value;
}

