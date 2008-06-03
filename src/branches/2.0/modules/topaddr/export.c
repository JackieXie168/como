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

/*
 * This module ranks addresses in terms of bytes.
 * The IP addresses can be destination or sources. 
 */
#include <assert.h>
#include "como.h"
#include "flowtable.h"
#include "data.h"
#include "uhash.h"

typedef struct ex_state ex_state_t;
struct ex_state {
    flowtable_t *table;
    size_t      nrec;
    timestamp_t current_ivl;
    uhash_t     hfunc;
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
record_cmp(topaddr_record_t **r1, topaddr_record_t **r2)
{
    return (*r1)->bytes == (*r2)->bytes ? 0 :
        ((*r1)->bytes > (*r2)->bytes ? -1 : 1);
}

static void
reinitialize_state(mdl_t *self, ex_state_t *st)
{
    st->nrec = 0;
    st->table = flowtable_new(MDL_MEM, 2048, NULL, (flow_match_fn)
                                tuple_matches_record, NULL);
}

/*
 * -- ex_init
 */
ex_state_t *
ex_init(mdl_t *self)
{
    ex_state_t *st = mdl_malloc(self, sizeof(ex_state_t));
    st->current_ivl = 0;
    uhash_initialize(&st->hfunc);
    reinitialize_state(self, st);
    return st;
}

/*
 * -- dump_state
 *
 * Stores all the records and reinitializes the state.
 */
static void
dump_state(mdl_t *self, ex_state_t *st)
{
    void * array[st->nrec];
    flowtable_iter_t it;
    size_t i;

    if (st->nrec == 0) /* nothing to do */
        return;

    /* dump all records into an array */
    i = 0;
    flowtable_iter_init(st->table, &it);
    while (flowtable_iter_next(&it)) {
        topaddr_record_t *rec = (topaddr_record_t *)flowtable_iter_get(&it);
        array[i++] = rec;
    }
    assert(i == st->nrec);

    /* sort the array using record_cmp */
    qsort(array, st->nrec, sizeof(void *),
            (int(*)(const void *, const void *))record_cmp);

    /* store up to 10 addresses */
    for (i = 0; i < MIN(10, st->nrec); i++)
        mdl_store_rec(self, array[i]);

    /* completely reset state */
    flowtable_destroy(st->table);
    reinitialize_state(self, st);
}

void
export(mdl_t * self, topaddr_tuple_t **tuples, size_t ntuples,
        timestamp_t ivl_start, ex_state_t *st)
{
    topaddr_record_t *rec;
    topaddr_config_t *cfg;
    topaddr_tuple_t *t;
    int eof, single_ivl, change_ivl;
    uint32_t hash;
    size_t i;

    if (ntuples == 0 && st->nrec == 0) /* nothing to do */
        return;

    if (st->current_ivl == 0) /* first tuples to arrive */
        st->current_ivl = ivl_start;

    cfg = mdl_get_config(self, topaddr_config_t);
    single_ivl = cfg->single_ivl;
    eof = ivl_start == ~0LLU;
    change_ivl = ivl_start != st->current_ivl;

    if (!single_ivl && change_ivl) { /* need store */
        dump_state(self, st);
        st->current_ivl = ivl_start;
    }

    for (i = 0; i < ntuples; i++) { /* update our state */
        t = tuples[i];

        hash = uhash(&st->hfunc, (uint8_t *) &t->addr, sizeof(uint32_t),
                UHASH_NEW);

        rec = (topaddr_record_t *) flowtable_lookup(st->table, hash,
                (pkt_t *)t);

        if (rec == NULL) {
            st->nrec++;
            rec = mdl_malloc(self, sizeof(topaddr_record_t));
            flowtable_insert(st->table, hash, (void *)rec);
            rec->addr = t->addr;
            rec->bytes = 0;
            rec->pkts = 0;
            rec->ts = ivl_start;
        }
        rec->bytes += t->bytes;
        rec->pkts += t->pkts;
    }

    if (single_ivl && eof) /* single ivl mode, flush all output */
        dump_state(self, st);
}

