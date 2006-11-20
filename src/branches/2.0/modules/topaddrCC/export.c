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

/*
 * This module ranks addresses in terms of bytes.
 * The IP addresses can be destination or sources. 
 */
#include <assert.h>
#include "como.h"
#include "flowtable.h"
#include "uhash.h"
#include "data.h"

typedef struct ex_state ex_state_t;
struct ex_state {
    flowtable_t *table;
    uhash_t     hfunc;
    size_t      nrec;
    timestamp_t current_ivl;
};

/*
 * auxiliary functions to store stuff in the flow table
 * and to sort records by traffic volume.
 */
static int
tuple_matches_record(topaddr_tuple_t *t, topaddr_record_t *r)
{
    return t->addr == r->addr;
}

static int
record_cmp(topaddr_record_t *r1, topaddr_record_t *r2)
{
    return r1->bytes == r2->bytes ? 0 :
        (r1->bytes > r2->bytes ? 1 : -1);
}

/*
 * -- ex_init
 */
void
ex_init(mdl_t *self)
{
    alc_t *alc = mdl_get_alloc(self);
    topaddr_config_t *cfg = mdl_get_config(self, topaddr_config_t);
    ex_state_t *st = mdl_malloc(self, sizeof(ex_state_t));

    uhash_initialize(&st->hfunc);

    st->table = flowtable_new(alc, 2048, NULL, (flow_match_fn) tuple_matches_record,
            NULL);

    st->nrec = 0;
    st->current_ivl = 0;
}


static void
store_records(mdl_t *self, ex_state_t *st)
{
    topaddr_record_t *rec;
    void * array[st->nrec];
    flowtable_iter_t it;
    size_t i;

    if (st->nrec == 0)
        return;

    flowtable_iter_init(st->table, &it);

    while ((rec = (topaddr_record_t *)flowtable_iter_get(&it))) {
        array[i] = rec;
        flowtable_iter_next(&it);
    }
    assert(i == st->nrec);

    qsort(array, i, sizeof(void *), (int(*)(const void *, const void *))record_cmp);
}

void
export(mdl_t * self, topaddr_tuple_t **tuples, size_t ntuples, timestamp_t ivl_start, 
        ex_state_t *st)
{
    topaddr_record_t *rec;
    topaddr_tuple_t *t;
    size_t i;

    if (ntuples == 0 && st->nrec == 0) /* nothing to do */
        return;

    if (st->current_ivl == 0)
        st->current_ivl = ivl_start;

    if (ivl_start != st->current_ivl) { /* need to store */
        store_records(self, st);

        /* completely reinitialize state */
        flowtable_destroy(st->table);
        ex_init(self);
        st->current_ivl = ivl_start;
    }

    for (i = 0; i < ntuples; i++) { /* update our state */
        t = tuples[i];
        rec = (topaddr_record_t *) flowtable_lookup(st->table, t->hash,
                (pkt_t *)t);

        if (rec == NULL) {
            rec = mem_mdl_malloc(self, sizeof(topaddr_record_t));
            rec->addr = t->addr;
            rec->bytes = 0;
            rec->pkts = 0;
        }
        rec->bytes += t->bytes;
        rec->pkts += t->pkts;
    }
    return;
}

