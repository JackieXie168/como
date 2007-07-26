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
 * $Id: topports.c 1012 2006-11-13 15:04:31Z jsanjuas $
 */

#include <stdlib.h> /* qsort */
#include <assert.h>

#include "como.h"
#include "data.h"

typedef struct entry entry_t;
struct entry {
    uint16_t port;
    uint64_t bytes;
};

#define NPORTS 65536

entry_t *
ex_init(mdl_t *self)
{
    entry_t *entries = mdl_malloc(self, sizeof(entry_t) * NPORTS);
    bzero(entries, sizeof(entry_t) * NPORTS);

    return entries;
}

int cmp_entries(const void *a, const void *b)
{
    return ((entry_t *)b)->bytes - ((entry_t *)a)->bytes;
}

void
store_entries(mdl_t *self, entry_t *entries, tuple_t *t, uint8_t proto, int top)
{
    uint64_t *bytes;
    uint32_t *pkts;
    uint16_t maxport;
    int i, j, idx;

    switch (proto) {
        case IPPROTO_TCP:
            bytes = t->tcpbytes;
            pkts = t->tcppkts;
            maxport = t->maxtcpport;
            break;
        case IPPROTO_UDP:
            bytes = t->udpbytes;
            pkts = t->udppkts;
            maxport = t->maxudpport;
            break;
    }

    /* prepare array with ports that have some traffic */
    idx = 0;
    for (i = 0; i < maxport; i++) {
        if (bytes[i] > 0) { /* skip zeros */
            entries[idx].port = i;
            entries[idx].bytes += bytes[i]; /* assume always bzeroed */
            idx++;
        }
    }

    /* sort */
    qsort(entries, idx, sizeof(entry_t), cmp_entries);

    /* store at most top records */
    for (i = 0; i < GETMIN(idx, top); i++) {
        record_t rec;

        rec.ts = t->ts;
        rec.proto = proto;
        rec.port = entries[i].port;
        rec.bytes = bytes[rec.port];
        rec.pkts = pkts[rec.port];
        
        mdl_store_rec(self, &rec);
    }

    /* clear array for later usage */
    bzero(entries, sizeof(entry_t) * idx);
}


void
export(mdl_t *self, tuple_t **tuples, size_t ntuples, timestamp_t ivl_start,
    entry_t *entries)
{
    config_t *config = mdl_get_config(self, config_t);
    tuple_t *t;
    int n;

    if (ntuples == 0)
        return;

    t = tuples[0];
    assert(ntuples == 1);
    store_entries(self, entries, t, IPPROTO_TCP, config->topn);
    store_entries(self, entries, t, IPPROTO_UDP, config->topn);
}

