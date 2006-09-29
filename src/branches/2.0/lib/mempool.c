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

#include <stdlib.h>

#include "corlib.h"

#define INITIAL_SIZE 128

struct mempool {
    size_t size;
    void **free_items;
    int fi_usage;
    int fi_size;
};

mempool_t *
mempool_new(size_t size)
{
    mempool_t *pool;

    pool = (mempool_t *) safe_malloc(sizeof(mempool_t));
    pool->size = size;
    pool->free_items = safe_calloc(INITIAL_SIZE, sizeof(void *));
    pool->fi_usage = 0;
    pool->fi_size = INITIAL_SIZE;

    return pool;
}

void
mempool_destroy(mempool_t *pool)
{
    int i;
    for (i = 0; i < pool->fi_usage; i++)
        free(pool->free_items[i]);
    free(pool);
}

void *
mempool_alloc(mempool_t *pool)
{
    if (pool->fi_usage == 0)
        return safe_malloc(pool->size);
    
    pool->fi_usage--; /* XXX shorten the array on low usage? */
    return pool->free_items[pool->fi_usage];
}

void
mempool_free(mempool_t *pool, void *elem)
{
    if (pool->fi_usage == pool->fi_size) { /* need larger free chunks list */
        pool->fi_size *= 2;
        pool->free_items = realloc(pool->free_items, sizeof(void *) * pool->fi_size);
    }

    pool->free_items[pool->fi_usage] = elem;
    pool->fi_usage++;
}

